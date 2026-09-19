// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <wallet/bcp1_watchonly.h>

#include <addresstype.h>
#include <chainparams.h>
#include <common/args.h>
#include <key.h>
#include <key_io.h>
#include <outputtype.h>
#include <pqkey.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <util/translation.h>
#include <wallet/bcp1_package.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/signer_provider.h>
#include <wallet/wallet.h>
#include <wallet/walletutil.h>

#include <algorithm>
#include <limits>
#include <string>
#include <variant>
#include <vector>

namespace wallet {
namespace {

const bilingual_str& PrivateSignRefusedMessage()
{
    static const bilingual_str msg = Untranslated(
        "Private keys are disabled for this wallet (BCP/1 exchange watch-only). "
        "Do not use signrawtransactionwithwallet, dumpprivkey, or exportpqkey; "
        "construct an unsigned package and sign externally.");
    return msg;
}

/** PQ seeds embedded in descriptors. HavePrivateKeys() is not used: public
 *  mr(hex) descriptors still render a ToPrivateString (the hex itself). */
bool WalletContainsPQSeeds(const CWallet& wallet)
{
    for (ScriptPubKeyMan* spk_man : wallet.GetAllScriptPubKeyMans()) {
        auto* desc_spk = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
        if (!desc_spk) continue;
        LOCK(desc_spk->cs_desc_man);
        const WalletDescriptor w_desc = desc_spk->GetWalletDescriptor();
        if (w_desc.descriptor && !w_desc.descriptor->ExtractAllPQSeeds().empty()) {
            return true;
        }
    }
    return false;
}

bool LooksLikePrivateToken(const std::string& s)
{
    if (s.empty()) return false;
    if (s.find("xprv") != std::string::npos) return true;
    if (DecodeSecret(s).IsValid()) return true;
    if (DecodeExtKey(s).key.IsValid()) return true;
    if (!IsHex(s)) return false;
    const std::vector<unsigned char> raw = ParseHex(s);
    return raw.size() == MLDSA44_SECRET_KEY_SIZE || raw.size() == SLHDSA128S_SECRET_KEY_SIZE;
}

bool ObjectHasPrivateField(const UniValue& obj, bilingual_str& err)
{
    static constexpr const char* kForbidden[] = {
        "privkey", "private_key", "wif", "seed", "pq_master_seed", "pq_seed",
        "xprv", "secret", "mnemonic", "xpriv", "master_seed",
    };
    for (const char* name : kForbidden) {
        if (obj.exists(name) && !obj[name].isNull()) {
            err = Untranslated("Deposit pool entries must not contain private key material");
            return true;
        }
    }
    return false;
}

bool DescriptorHasPrivateMaterial(const Descriptor& desc, const FlatSigningProvider& keys)
{
    if (!keys.keys.empty() || !keys.pq_keys.empty()) return true;
    return !desc.ExtractAllPQSeeds().empty();
}

std::string WithChecksum(const std::string& descriptor)
{
    if (descriptor.find('#') != std::string::npos) return descriptor;
    return AddChecksum(descriptor);
}

bool PubkeyHexToDescriptor(const std::string& hex_or_slh, std::string& descriptor, bilingual_str& err)
{
    std::string body = hex_or_slh;
    bool wrapped_slh = false;
    if (body.rfind("pk_slh(", 0) == 0 && body.size() > 8 && body.back() == ')') {
        wrapped_slh = true;
        body = body.substr(7, body.size() - 8);
    }
    if (!IsHex(body)) {
        err = Untranslated("Deposit pool pubkey must be hex or pk_slh(hex)");
        return false;
    }
    const std::vector<unsigned char> pubkey = ParseHex(ToLower(body));
    if (wrapped_slh) {
        if (pubkey.size() != SLHDSA128S_PUBKEY_SIZE) {
            err = Untranslated(strprintf("pk_slh() key must be %u bytes, got %u",
                                         SLHDSA128S_PUBKEY_SIZE, pubkey.size()));
            return false;
        }
        descriptor = "mr(pk_slh(" + HexStr(pubkey) + "))";
        return true;
    }
    if (pubkey.size() == MLDSA44_PUBKEY_SIZE) {
        descriptor = "mr(" + HexStr(pubkey) + ")";
        return true;
    }
    if (pubkey.size() == SLHDSA128S_PUBKEY_SIZE) {
        descriptor = "mr(pk_slh(" + HexStr(pubkey) + "))";
        return true;
    }
    if (pubkey.size() == MLDSA44_SECRET_KEY_SIZE || pubkey.size() == SLHDSA128S_SECRET_KEY_SIZE) {
        err = Untranslated("Deposit pool refuses PQ secret keys");
        return false;
    }
    err = Untranslated(strprintf("Unsupported PQ pubkey size %u bytes (expected ML-DSA %u or SLH-DSA %u)",
                                 pubkey.size(), MLDSA44_PUBKEY_SIZE, SLHDSA128S_PUBKEY_SIZE));
    return false;
}

// Default monetary wallet tree is mr(pqhd(...), pk_slh(pqhd(...))) — two leaves.
// A single-leaf mr(ML-DSA) does not commit to the same merkle root.
bool TwoLeafWalletDescriptor(const std::string& ml_hex, const std::string& slh_hex, std::string& descriptor, bilingual_str& err)
{
    std::string ml_desc;
    if (!PubkeyHexToDescriptor(ml_hex, ml_desc, err)) return false;
    if (ml_desc.rfind("mr(", 0) != 0 || ml_desc.find("pk_slh(") != std::string::npos) {
        err = Untranslated("Two-leaf deposit pool first key must be ML-DSA-44");
        return false;
    }
    const std::string ml_inner = ml_desc.substr(3, ml_desc.size() - 4); // strip mr( )

    std::string slh = slh_hex;
    if (slh.rfind("pk_slh(", 0) == 0 && slh.size() > 8 && slh.back() == ')') {
        slh = slh.substr(7, slh.size() - 8);
    }
    if (!IsHex(slh)) {
        err = Untranslated("Two-leaf deposit pool SLH-DSA pubkey must be hex or pk_slh(hex)");
        return false;
    }
    const std::vector<unsigned char> slh_pub = ParseHex(ToLower(slh));
    if (slh_pub.size() != SLHDSA128S_PUBKEY_SIZE) {
        err = Untranslated(strprintf("Two-leaf SLH-DSA pubkey must be %u bytes, got %u",
                                     SLHDSA128S_PUBKEY_SIZE, slh_pub.size()));
        return false;
    }
    descriptor = "mr(" + ml_inner + ",pk_slh(" + HexStr(slh_pub) + "))";
    return true;
}

bool AddressToDescriptor(const std::string& address, std::string& descriptor, bilingual_str& err)
{
    std::string dest_err;
    const CTxDestination dest = DecodeDestination(address, dest_err);
    if (!IsValidDestination(dest)) {
        err = Untranslated(dest_err.empty() ? "Invalid BTX address" : dest_err);
        return false;
    }
    if (OutputTypeFromDestination(dest) != OutputType::P2MR) {
        err = Untranslated("Deposit pool addresses must be P2MR");
        return false;
    }
    descriptor = "addr(" + address + ")";
    return true;
}

bool ImportPublicDescriptor(CWallet& wallet, const std::string& descriptor, const std::string& label, bilingual_str& err)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (LooksLikePrivateToken(descriptor)) {
        err = Untranslated("Deposit pool refuses private key material");
        return false;
    }

    FlatSigningProvider keys;
    std::string parse_err;
    const std::string checksummed = WithChecksum(descriptor);
    auto parsed = Parse(checksummed, keys, parse_err, /*require_checksum=*/true);
    if (parsed.empty() || !parsed[0]) {
        err = Untranslated(parse_err.empty() ? "Failed to parse deposit pool descriptor" : parse_err);
        return false;
    }
    if (parsed.size() != 1) {
        err = Untranslated("Deposit pool does not accept multipath descriptors");
        return false;
    }

    auto desc = std::move(parsed[0]);
    if (DescriptorHasPrivateMaterial(*desc, keys)) {
        err = Untranslated("Deposit pool refuses descriptors that contain private keys or PQ seeds. "
                           "ML-DSA has no non-hardened public child derivation; import addresses or pubkeys.");
        return false;
    }

    std::vector<CScript> scripts;
    FlatSigningProvider expand_keys;
    if (!desc->Expand(/*pos=*/0, keys, scripts, expand_keys)) {
        err = Untranslated("Cannot expand deposit descriptor without private keys. "
                           "Ranged mr()/pqhd() watch-only imports are unsupported; "
                           "use a pre-generated address or pubkey pool.");
        return false;
    }
    if (DescriptorHasPrivateMaterial(*desc, expand_keys)) {
        err = Untranslated("Deposit pool expansion produced private keys");
        return false;
    }
    if (scripts.empty()) {
        err = Untranslated("Deposit descriptor expanded to no scripts");
        return false;
    }
    for (const CScript& script : scripts) {
        int witness_version{-1};
        std::vector<unsigned char> witness_program;
        if (!script.IsWitnessProgram(witness_version, witness_program) ||
            witness_version != 2 || witness_program.size() != WITNESS_V2_P2MR_SIZE) {
            err = Untranslated("Deposit pool descriptors must produce P2MR outputs");
            return false;
        }
    }

    WalletDescriptor w_desc(std::move(desc), static_cast<uint64_t>(GetTime()),
                            /*range_start=*/0, /*range_end=*/1, /*next_index=*/0);
    if (!wallet.AddWalletDescriptor(w_desc, expand_keys, label, /*internal=*/false)) {
        err = Untranslated(strprintf("Could not add deposit descriptor '%s'", checksummed));
        return false;
    }
    return true;
}

bool ItemToDescriptorAndLabel(const UniValue& item, size_t index, std::string& descriptor, std::string& label, bilingual_str& err)
{
    label = "bcp1-deposit";
    if (item.isStr()) {
        const std::string s = item.get_str();
        if (LooksLikePrivateToken(s)) {
            err = Untranslated("Deposit pool refuses private key material");
            return false;
        }
        std::string dest_err;
        const CTxDestination dest = DecodeDestination(s, dest_err);
        if (IsValidDestination(dest)) {
            return AddressToDescriptor(s, descriptor, err);
        }
        if (s.rfind("pk_slh(", 0) == 0 || (IsHex(s) && (s.size() == MLDSA44_PUBKEY_SIZE * 2 ||
                                                        s.size() == SLHDSA128S_PUBKEY_SIZE * 2))) {
            return PubkeyHexToDescriptor(s, descriptor, err);
        }
        if (s.find('(') != std::string::npos) {
            descriptor = s;
            return true;
        }
        if (IsHex(s)) {
            return PubkeyHexToDescriptor(s, descriptor, err);
        }
        err = Untranslated(dest_err.empty() ? strprintf("Deposit pool item %u is not a P2MR address, pubkey, or descriptor", index)
                                            : dest_err);
        return false;
    }

    if (!item.isObject()) {
        err = Untranslated(strprintf("Deposit pool item %u must be a string or object", index));
        return false;
    }
    if (ObjectHasPrivateField(item, err)) return false;

    if (item.exists("label") && item["label"].isStr()) {
        label = item["label"].get_str();
    } else if (item.exists("index") && !item["index"].isNull()) {
        uint32_t branch = 0;
        uint32_t account = 0;
        if (item.exists("branch") && item["branch"].isNum()) {
            const int64_t b = item["branch"].getInt<int64_t>();
            if (b == 0 || b == 1) branch = static_cast<uint32_t>(b);
        }
        if (item.exists("account") && item["account"].isNum()) {
            const int64_t a = item["account"].getInt<int64_t>();
            if (a >= 0 && a <= static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
                account = static_cast<uint32_t>(a);
            }
        }
        label = strprintf("%u/%s/%s", account, branch == 1 ? "change" : "deposit", item["index"].getValStr());
    }

    if (item.exists("desc") && item["desc"].isStr()) {
        descriptor = item["desc"].get_str();
        return true;
    }
    // Default wallet P2MR is a 2-leaf tree (ML-DSA + SLH-DSA backup). A
    // single-leaf mr(pubkey) watches a different scriptPubKey than
    // getnewaddress(p2mr). Prefer the two-leaf form when both pubkeys exist.
    const bool have_ml = item.exists("pubkey") && item["pubkey"].isStr();
    const std::string slh = item.exists("pubkey_slh") && item["pubkey_slh"].isStr() ? item["pubkey_slh"].get_str() :
                            item.exists("slh_pubkey") && item["slh_pubkey"].isStr() ? item["slh_pubkey"].get_str() : "";
    const std::string address = item.exists("address") && item["address"].isStr() ? item["address"].get_str() : "";
    auto verify_address = [&](const std::string& computed) -> bool {
        if (address.empty()) return true;
        if (computed == address) return true;
        err = Untranslated("Deposit pool pubkey(s) do not commit to the given P2MR address. "
                           "Default wallet trees are two-leaf ML-DSA+SLH-DSA; pass pubkey and pubkey_slh.");
        return false;
    };
    if (have_ml && !slh.empty()) {
        if (!TwoLeafWalletDescriptor(item["pubkey"].get_str(), slh, descriptor, err)) return false;
        const auto ml_bytes = ParseHex(ToLower(item["pubkey"].get_str()));
        std::string slh_hex = slh;
        if (slh_hex.rfind("pk_slh(", 0) == 0 && slh_hex.size() > 8 && slh_hex.back() == ')') {
            slh_hex = slh_hex.substr(7, slh_hex.size() - 8);
        }
        const auto slh_bytes = ParseHex(ToLower(slh_hex));
        return verify_address(bcp1::EncodeP2MRFromPubkeys(ml_bytes, slh_bytes));
    }
    if (have_ml) {
        if (!PubkeyHexToDescriptor(item["pubkey"].get_str(), descriptor, err)) return false;
        const auto ml_bytes = ParseHex(ToLower(item["pubkey"].get_str()));
        if (!address.empty() && !verify_address(bcp1::EncodeP2MRFromPubkeys(ml_bytes, {}))) {
            return false;
        }
        return true;
    }
    if (!address.empty()) {
        return AddressToDescriptor(address, descriptor, err);
    }

    err = Untranslated(strprintf("Deposit pool object %u needs address, pubkey, or desc", index));
    return false;
}

bool ScriptIsP2MR(const CScript& script)
{
    int witness_version{-1};
    std::vector<unsigned char> witness_program;
    return script.IsWitnessProgram(witness_version, witness_program) &&
           witness_version == 2 && witness_program.size() == WITNESS_V2_P2MR_SIZE;
}

bool IsDecimalIndex(const std::string& s)
{
    return !s.empty() && std::all_of(s.begin(), s.end(), [](unsigned char c) { return c >= '0' && c <= '9'; });
}

/** Structured pool labels only: "bcp1-deposit", "deposit/<i>", "change/<i>", "<account>/deposit/<i>". */
bool LabelLooksLikePool(const std::string& label)
{
    if (label == "bcp1-deposit") return true;
    const auto slash = label.rfind('/');
    if (slash == std::string::npos || slash + 1 >= label.size()) return false;
    if (!IsDecimalIndex(label.substr(slash + 1))) return false;
    const auto prev = (slash == 0) ? std::string::npos : label.rfind('/', slash - 1);
    const std::string mid = (prev == std::string::npos) ? label.substr(0, slash) : label.substr(prev + 1, slash - prev - 1);
    if (mid != "deposit" && mid != "change") return false;
    if (prev == std::string::npos) return true;
    return IsDecimalIndex(label.substr(0, prev));
}

bool IsFailClosedStubBackend(const std::string& backend)
{
    return backend == "pkcs11" || backend == "kmip" || backend == "https";
}

void StampStubNotLive(UniValue& o)
{
    o.pushKV("pkcs11_live", false);
    o.pushKV("kmip_live", false);
    o.pushKV("https_live", false);
}

} // namespace

bool ExchangeWatchOnlyNodeEnabled(const ArgsManager& args)
{
    return args.GetBoolArg(EXCHANGE_WATCHONLY_ARG, false);
}

uint64_t ExchangeWatchOnlyCreateFlags(const ArgsManager& args)
{
    uint64_t flags = WALLET_FLAG_DISABLE_PRIVATE_KEYS | WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET;
#ifdef ENABLE_EXTERNAL_SIGNER
    if (!args.GetArg("-signer", "").empty()) {
        flags |= WALLET_FLAG_EXTERNAL_SIGNER;
    }
#else
    (void)args;
#endif
    return flags;
}

void ApplyExchangeWatchOnlyCreateFlags(uint64_t& create_flags, const ArgsManager& args)
{
    if (!ExchangeWatchOnlyNodeEnabled(args)) return;
    create_flags |= ExchangeWatchOnlyCreateFlags(args);
}

bool ApplyExchangeWatchOnlyArgs(const ArgsManager& args, bilingual_str& err)
{
    if (!ExchangeWatchOnlyNodeEnabled(args)) return true;
    if (args.GetBoolArg("-disablewallet", DEFAULT_DISABLE_WALLET)) {
        err = Untranslated("-exchange-watchonly requires the wallet; do not combine with -disablewallet");
        return false;
    }
    return true;
}

bool EnsureExchangeWatchOnly(const CWallet& wallet, const ArgsManager& args, bilingual_str& err)
{
    if (!ExchangeWatchOnlyNodeEnabled(args)) return true;
    return EnsureExchangeWatchOnly(wallet, err);
}

bool EnsureExchangeWatchOnly(const CWallet& wallet, bilingual_str& err)
{
    if (!wallet.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        err = Untranslated("BCP/1 exchange watch-only requires a descriptor wallet");
        return false;
    }
    if (!wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        err = Untranslated("BCP/1 exchange watch-only requires disable_private_keys "
                           "(createwallet disable_private_keys=true, or recreate the wallet)");
        return false;
    }
    LOCK(wallet.cs_wallet);
    if (WalletContainsPQSeeds(wallet)) {
        err = Untranslated("BCP/1 exchange watch-only refuses wallets that contain PQ master seeds");
        return false;
    }
    return true;
}

bool ExchangeWatchOnlyActive(const CWallet& wallet)
{
    // Opt-in: -exchange-watchonly is a node-level switch. Without it, a
    // descriptor disable_private_keys wallet is a hardware / external-signer
    // wallet, not a BCP/1 custody wallet, and must keep signing.
    if (!gArgs.GetBoolArg(EXCHANGE_WATCHONLY_ARG, false)) return false;
    if (!wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) return false;
    if (!wallet.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) return false;
    // Full profile is DISABLE_PRIVATE_KEYS + EXTERNAL_SIGNER. Deposit-pool
    // wallets omit EXTERNAL_SIGNER and still count as exchange watch-only.
    return true;
}

bool RefusePrivateSign(const CWallet& wallet, bilingual_str& err)
{
    if (!ExchangeWatchOnlyActive(wallet)) return false;
    err = PrivateSignRefusedMessage();
    return true;
}

bool CanDelegateExternalPsbtSign(const CWallet& wallet)
{
#ifdef ENABLE_EXTERNAL_SIGNER
    return wallet.IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER);
#else
    (void)wallet;
    return false;
#endif
}

bool ImportDepositPool(CWallet& wallet, const UniValue& addresses_or_pubkeys, bilingual_str& err)
{
    UniValue unused;
    return ImportDepositPool(wallet, addresses_or_pubkeys, err, unused);
}

bool ImportDepositPool(CWallet& wallet, const UniValue& addresses_or_pubkeys, bilingual_str& err, UniValue& details)
{
    if (!wallet.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        err = Untranslated("importdepositpool requires a descriptor wallet");
        return false;
    }
    if (!wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        err = Untranslated("Cannot import a deposit pool into a wallet with private keys enabled");
        return false;
    }

    UniValue items(UniValue::VARR);
    if (addresses_or_pubkeys.isArray()) {
        items = addresses_or_pubkeys;
    } else if (addresses_or_pubkeys.isStr() || addresses_or_pubkeys.isObject()) {
        items.push_back(addresses_or_pubkeys);
    } else {
        err = Untranslated("importdepositpool expects an array of addresses, pubkeys, or descriptor objects");
        return false;
    }

    LOCK(wallet.cs_wallet);
    if (WalletContainsPQSeeds(wallet)) {
        err = Untranslated("Cannot import a deposit pool into a wallet that contains PQ master seeds");
        return false;
    }

    int imported = 0;
    int address_only = 0;
    for (size_t i = 0; i < items.size(); ++i) {
        std::string descriptor;
        std::string label;
        if (!ItemToDescriptorAndLabel(items[i], i, descriptor, label, err)) return false;
        if (descriptor.rfind("addr(", 0) == 0) ++address_only;
        if (!ImportPublicDescriptor(wallet, descriptor, label, err)) return false;
        ++imported;
    }
    details = UniValue(UniValue::VOBJ);
    details.pushKV("imported", imported);
    details.pushKV("address_only", address_only);
    details.pushKV("solvable", address_only == 0);
    if (address_only > 0) {
        details.pushKV("warning",
                       "addr() pool entries watch deposits but cannot fill P2MR signing digests. "
                       "Import pubkey + pubkey_slh (or a public mr(...) descriptor) for withdrawals.");
    }
    return true;
}

UniValue CommandSignerHealthReport(const ArgsManager& args)
{
    UniValue o(UniValue::VOBJ);
    StampStubNotLive(o);
    const std::string cmd = args.GetArg("-signer", "");
    if (cmd.empty()) {
        o.pushKV("available", false);
        o.pushKV("ok", false);
        o.pushKV("backend", "none");
        return o;
    }
    std::string error;
    auto signer = MakeCommandSigner(cmd, Params().GetChainTypeString(), std::nullopt, error);
    if (!signer) {
        o.pushKV("available", false);
        o.pushKV("ok", false);
        o.pushKV("error", error.empty() ? "signer unavailable" : error);
        o.pushKV("backend", "command");
        return o;
    }
    const std::string backend = signer->Backend();
    UniValue health = signer->Health();
    if (!health.isObject()) health = UniValue(UniValue::VOBJ);
    if (IsFailClosedStubBackend(backend)) {
        health.pushKV("ok", false);
        health.pushKV("available", false);
        health.pushKV("backend", backend);
        if (!health.exists("error")) {
            health.pushKV("error", backend == "pkcs11" ? SignerProvider::ERR_PKCS11_UNAVAILABLE :
                                   backend == "kmip" ? SignerProvider::ERR_KMIP_UNAVAILABLE :
                                   SignerProvider::ERR_HTTPS_UNAVAILABLE);
        }
        StampStubNotLive(health);
        return health;
    }
    const bool ok = health.exists("ok") && health["ok"].isBool() && health["ok"].get_bool();
    const bool command_ok = backend == "command" && ok;
    health.pushKV("available", command_ok);
    health.pushKV("ok", command_ok);
    health.pushKV("backend", backend.empty() ? "command" : backend);
    StampStubNotLive(health);
    return health;
}

bool WalletHasDepositMaterial(const CWallet& wallet)
{
    if (!wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) return false;
    if (WalletContainsPQSeeds(wallet)) return false;
    LOCK(wallet.cs_wallet);
    // Address-book hits require a structured pool label AND a P2MR dest.
    // A bare setlabel on a P2MR receive address must not flip deposits_ok.
    for (const auto& [dest, entry] : wallet.m_address_book) {
        if (!std::holds_alternative<WitnessV2P2MR>(dest)) continue;
        if (LabelLooksLikePool(entry.GetLabel())) return true;
    }
    for (ScriptPubKeyMan* man : wallet.GetAllScriptPubKeyMans()) {
        if (!man) continue;
        for (const CScript& script : man->GetScriptPubKeys()) {
            if (ScriptIsP2MR(script)) return true;
        }
    }
    return false;
}

Bcp1Readiness EvaluateBcp1Readiness(const CWallet& wallet, const ArgsManager& args)
{
    Bcp1Readiness r;
    r.descriptors_ok = wallet.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS);
    r.watchonly_ok = wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) && !WalletContainsPQSeeds(wallet);
    r.synced_ok = !wallet.chain().isInitialBlockDownload();
    r.deposits_ok = WalletHasDepositMaterial(wallet);
    r.signer_health = CommandSignerHealthReport(args);
    r.signer_ok = r.signer_health.exists("available") && r.signer_health["available"].isTrue();
    r.pkcs11_live = false;
    r.kmip_live = false;
    r.https_live = false;
    return r;
}

} // namespace wallet
