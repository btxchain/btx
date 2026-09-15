// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/model_funding.h>

#include <addresstype.h>
#include <coins.h>
#include <consensus/amount.h>
#include <core_io.h>
#include <crypto/sha256.h>
#include <key_io.h>
#include <modelnet/types.h>
#include <pqkey.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <script/signingprovider.h>
#include <span.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/coincontrol.h>
#include <wallet/rpc/util.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <initializer_list>
#include <limits>
#include <map>
#include <tinyformat.h>
#include <uint256.h>

namespace wallet {
namespace {

const UniValue* FindField(const UniValue& o, std::initializer_list<const char*> names)
{
    if (!o.isObject()) return nullptr;
    for (const char* name : names) {
        if (o.exists(name) && !o[name].isNull()) return &o[name];
    }
    return nullptr;
}

bool ContainsForbiddenHtlcToken(const std::string& s)
{
    return s.find("htlc_sha256_tx") != std::string::npos ||
           s.find("htlc_tx(") != std::string::npos ||
           s.find("buildmodelhtlcclaim") != std::string::npos;
}

} // namespace

bool RejectForbiddenHtlc(const UniValue& options, std::string& err)
{
    if (!options.isObject()) return true;
    if (const UniValue* htlc = FindField(options, {"htlc", "template", "htlc_template"})) {
        if (!htlc->isStr()) {
            err = "htlc must be the string \"htlc_sha256\"";
            return false;
        }
        if (htlc->get_str() != "htlc_sha256") {
            err = "new model funding must use htlc_sha256; HASH160 htlc_tx is recovery-only";
            return false;
        }
    }
    for (const char* name : {"htlc_sha256_tx", "htlc_tx", "hash160", "secret", "secret32", "secret32_hex", "seed", "mnemonic", "service_sk"}) {
        if (options.exists(name) && !options[name].isNull()) {
            err = "HASH160 htlc_tx / secrets are not accepted on preparemodelfunding; reuse 0.34.6 htlc_sha256";
            return false;
        }
    }
    if (options.exists("descriptor") && options["descriptor"].isStr() &&
        ContainsForbiddenHtlcToken(options["descriptor"].get_str())) {
        err = "HASH160 htlc_tx is recovery-only; model funding uses htlc_sha256";
        return false;
    }
    return true;
}

bool RejectAutoPay(const UniValue& options, std::string& err)
{
    if (!options.isObject()) return true;
    if (const UniValue* auto_pay = FindField(options, {"auto_pay", "autopay", "automatic_spend"})) {
        if (auto_pay->isBool() && auto_pay->get_bool()) {
            err = "auto_pay is refused; automatic BTX spend is zero";
            return false;
        }
        if (auto_pay->isNum() && auto_pay->getInt<int64_t>() != 0) {
            err = "automatic BTX spend is zero; explicit prepare/sign/submit required";
            return false;
        }
    }
    return true;
}

bool ValidateFundingAmount(int64_t amount_atoms, std::string& err)
{
    if (amount_atoms < 0) {
        err = "amount_atoms must not be negative";
        return false;
    }
    if (amount_atoms == 0) {
        err = "amount_atoms must be positive";
        return false;
    }
    if (!MoneyRange(amount_atoms)) {
        err = "amount_atoms out of MoneyRange";
        return false;
    }
    return true;
}

bool NormalizePqDescriptorKey(const std::string& in, std::string& out, std::string& err)
{
    std::string s = in;
    if (s.empty()) {
        err = "PQ key is empty";
        return false;
    }
    if (s.rfind("pk_slh(", 0) == 0) {
        out = s;
        return true;
    }
    if (s.rfind("pqhd(", 0) == 0) {
        out = s;
        return true;
    }
    if (IsHex(s)) {
        s = ToLower(s);
        const std::vector<unsigned char> key = ParseHex(s);
        if (key.size() == MLDSA44_PUBKEY_SIZE) {
            out = HexStr(key);
            return true;
        }
        if (key.size() == SLHDSA128S_PUBKEY_SIZE) {
            out = strprintf("pk_slh(%s)", HexStr(key));
            return true;
        }
        err = strprintf("claimant/refund key must be ML-DSA (%u bytes) or SLH-DSA (%u bytes), got %u",
                        MLDSA44_PUBKEY_SIZE, SLHDSA128S_PUBKEY_SIZE, key.size());
        return false;
    }
    std::string dest_err;
    const CTxDestination dest = DecodeDestination(s, dest_err);
    if (IsValidDestination(dest)) {
        err = "htlc_sha256 leaves require a PQ pubkey hex (or pk_slh(...)), not a payment address";
        return false;
    }
    err = dest_err.empty() ? "claimant/refund key is not a PQ pubkey hex" : dest_err;
    return false;
}

bool ExpandHtlcSha256Descriptor(const std::string& descriptor, CScript& script_pubkey, std::string& canonical, std::string& err)
{
    if (ContainsForbiddenHtlcToken(descriptor)) {
        err = "HASH160 htlc_tx is recovery-only; model funding uses htlc_sha256";
        return false;
    }
    FlatSigningProvider provider;
    std::string parse_err;
    auto parsed = Parse(descriptor, provider, parse_err, /*require_checksum=*/false);
    if (parsed.empty() || !parsed[0]) {
        err = parse_err.empty() ? "descriptor parse failed" : parse_err;
        return false;
    }
    canonical = parsed[0]->ToString();
    if (canonical.find("htlc_sha256(") == std::string::npos) {
        err = "descriptor must be mr(htlc_sha256(<SHA256>,<claimer>),refund(<height>,<sender>))";
        return false;
    }
    if (ContainsForbiddenHtlcToken(canonical)) {
        err = "HASH160 htlc_tx is recovery-only; model funding uses htlc_sha256";
        return false;
    }
    std::vector<CScript> scripts;
    FlatSigningProvider out;
    if (!parsed[0]->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, scripts, out) || scripts.size() != 1) {
        err = "descriptor expand failed";
        return false;
    }
    script_pubkey = scripts[0];
    return true;
}

bool BuildHtlcSha256Descriptor(FrozenFundingQuote& q, std::string& err)
{
    if (q.key_hash_hex.empty() || q.claimant_key.empty() || q.refund_key.empty()) {
        err = "key_hash, claimant pubkey, and refund_pubkey are required";
        return false;
    }
    if (q.refund_height == 0) {
        err = "refund_height must be a positive CLTV height";
        return false;
    }
    modelnet::Hash32 key_hash;
    std::string hash_err;
    if (!modelnet::Hash32::FromHex(ToLower(q.key_hash_hex), key_hash, hash_err)) {
        err = hash_err.empty() ? "key_hash must be 32-byte SHA-256 hex" : hash_err;
        return false;
    }
    q.key_hash_hex = key_hash.Hex();
    std::string claimant;
    std::string refund;
    if (!NormalizePqDescriptorKey(q.claimant_key, claimant, err)) return false;
    if (!NormalizePqDescriptorKey(q.refund_key, refund, err)) return false;
    q.claimant_key = claimant;
    q.refund_key = refund;
    const std::string body = strprintf("mr(htlc_sha256(%s,%s),refund(%u,%s))",
                                        q.key_hash_hex, q.claimant_key, q.refund_height, q.refund_key);
    const std::string with_checksum = AddChecksum(body);
    std::string canonical;
    if (!ExpandHtlcSha256Descriptor(with_checksum, q.output_script, canonical, err)) return false;
    q.descriptor = canonical;
    return true;
}

bool ParseFrozenFundingQuote(const UniValue& options, FrozenFundingQuote& q, std::string& err)
{
    if (options.isNull() || options.empty()) return true;
    if (!options.isObject()) {
        err = "options must be an object";
        return false;
    }
    if (!RejectForbiddenHtlc(options, err)) return false;
    if (!RejectAutoPay(options, err)) return false;

    if (const UniValue* v = FindField(options, {"release_id"})) q.release_id = v->get_str();
    if (const UniValue* v = FindField(options, {"key_hash"})) q.key_hash_hex = ToLower(v->get_str());
    if (const UniValue* v = FindField(options, {"claimant", "claimant_pubkey"})) q.claimant_key = v->get_str();
    if (const UniValue* v = FindField(options, {"refund_pubkey", "refund_key"})) q.refund_key = v->get_str();
    if (const UniValue* v = FindField(options, {"descriptor"})) q.descriptor = v->get_str();
    if (const UniValue* v = FindField(options, {"unsigned_hex"})) q.unsigned_hex = v->get_str();

    if (const UniValue* v = FindField(options, {"refund_height"})) {
        if (!v->isNum()) {
            err = "refund_height must be an integer";
            return false;
        }
        const int64_t h = v->getInt<int64_t>();
        if (h <= 0 || h > static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
            err = "refund_height out of range";
            return false;
        }
        q.refund_height = static_cast<uint32_t>(h);
    }
    if (const UniValue* v = FindField(options, {"amount_atoms", "max_atoms"})) {
        if (!v->isNum()) {
            err = "amount_atoms must be an integer";
            return false;
        }
        q.amount_atoms = v->getInt<int64_t>();
        if (!ValidateFundingAmount(q.amount_atoms, err)) return false;
    }
    if (const UniValue* v = FindField(options, {"fee_cap_atoms"})) {
        if (!v->isNum()) {
            err = "fee_cap_atoms must be an integer";
            return false;
        }
        q.fee_cap_atoms = v->getInt<int64_t>();
        if (q.fee_cap_atoms < 0) {
            err = "fee_cap_atoms must not be negative";
            return false;
        }
    }
    if (const UniValue* v = FindField(options, {"output_script"})) {
        if (!v->isStr() || !IsHex(v->get_str())) {
            err = "output_script must be hex";
            return false;
        }
        const auto raw = ParseHex(v->get_str());
        q.output_script = CScript(raw.begin(), raw.end());
    }
    if (const UniValue* v = FindField(options, {"unsigned_txid"})) {
        const auto parsed = uint256::FromHex(v->get_str());
        if (!parsed) {
            err = "unsigned_txid must be 32-byte hex";
            return false;
        }
        q.unsigned_txid = *parsed;
    }

    if (!q.unsigned_hex.empty()) {
        CMutableTransaction tx;
        if (!DecodeFundingTxHex(q.unsigned_hex, tx, err)) return false;
        if (q.unsigned_txid.IsNull()) q.unsigned_txid = tx.GetHash().ToUint256();
    }
    if (!q.descriptor.empty() && q.output_script.empty()) {
        std::string canonical;
        if (!ExpandHtlcSha256Descriptor(q.descriptor, q.output_script, canonical, err)) return false;
        q.descriptor = canonical;
    }
    return true;
}

void MergeHelperCampaign(const UniValue& helper, const std::string& release_id, FrozenFundingQuote& q)
{
    (void)helper;
    (void)release_id;
    (void)q;
    // GAP-12: helper cannot supply amount, refund key, claimant, or locktime.
}

bool DecodeFundingTxHex(const std::string& hex, CMutableTransaction& tx, std::string& err)
{
    if (!DecodeHexTx(tx, hex, /*try_no_witness=*/true, /*try_witness=*/true)) {
        err = "TX decode failed. Make sure the hex is a serialized transaction.";
        return false;
    }
    if (tx.vout.empty()) {
        err = "funding transaction has no outputs";
        return false;
    }
    return true;
}

bool MatchFrozenTemplate(const FrozenFundingQuote& frozen, const CMutableTransaction& tx, std::string& err)
{
    if (frozen.unsigned_txid.IsNull() && frozen.output_script.empty()) {
        err = "frozen funding template required; pass preparemodelfunding result as options";
        return false;
    }
    // Signing fills scriptSig/witness and therefore the txid. Freeze the
    // unsigned skeleton (prevouts, sequences, outputs, version, locktime).
    CMutableTransaction skeleton = tx;
    for (auto& in : skeleton.vin) {
        in.scriptSig.clear();
        in.scriptWitness.SetNull();
    }
    const uint256 txid = tx.GetHash().ToUint256();
    const uint256 skeleton_txid = skeleton.GetHash().ToUint256();
    if (!frozen.unsigned_txid.IsNull() && txid != frozen.unsigned_txid && skeleton_txid != frozen.unsigned_txid) {
        err = "funding template txid mutated; run preparemodelfunding again";
        return false;
    }
    if (!frozen.output_script.empty()) {
        bool found = false;
        for (const auto& out : tx.vout) {
            if (out.scriptPubKey == frozen.output_script) {
                if (frozen.amount_atoms > 0 && out.nValue != frozen.amount_atoms) {
                    err = "HTLC output amount changed; run preparemodelfunding again";
                    return false;
                }
                found = true;
                break;
            }
        }
        if (!found) {
            err = "HTLC output script missing or changed; run preparemodelfunding again";
            return false;
        }
    }
    return true;
}

UniValue FrozenQuoteToJson(const FrozenFundingQuote& q)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 2);
    o.pushKV("frozen", true);
    if (!q.release_id.empty()) o.pushKV("release_id", q.release_id);
    if (!q.key_hash_hex.empty()) o.pushKV("key_hash", q.key_hash_hex);
    if (!q.claimant_key.empty()) o.pushKV("claimant", q.claimant_key);
    if (!q.refund_key.empty()) o.pushKV("refund_pubkey", q.refund_key);
    if (q.refund_height > 0) o.pushKV("refund_height", static_cast<int64_t>(q.refund_height));
    if (q.amount_atoms > 0) o.pushKV("amount_atoms", q.amount_atoms);
    o.pushKV("fee_cap_atoms", q.fee_cap_atoms);
    o.pushKV("fee_atoms", q.fee_atoms);
    if (!q.descriptor.empty()) o.pushKV("descriptor", q.descriptor);
    if (!q.output_script.empty()) o.pushKV("output_script", HexStr(q.output_script));
    if (!q.unsigned_hex.empty()) o.pushKV("unsigned_hex", q.unsigned_hex);
    if (!q.unsigned_txid.IsNull()) o.pushKV("unsigned_txid", q.unsigned_txid.GetHex());
    o.pushKV("automatic_spend", 0);
    o.pushKV("htlc", "htlc_sha256");
    o.pushKV("note", "Never signed here. signmodelfunding then submitmodelfunding. Claim/refund via buildhtlcclaim / buildhtlcrefund.");
    return o;
}

UniValue ExportModelRecoveryJson(const FrozenFundingQuote& q)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 2);
    if (!q.release_id.empty()) o.pushKV("release_id", q.release_id);
    if (!q.descriptor.empty()) o.pushKV("descriptor", q.descriptor);
    if (!q.key_hash_hex.empty()) o.pushKV("key_hash", q.key_hash_hex);
    if (q.refund_height > 0) o.pushKV("refund_height", static_cast<int64_t>(q.refund_height));
    if (!q.output_script.empty()) {
        o.pushKV("output_script", HexStr(q.output_script));
        CTxDestination dest;
        if (ExtractDestination(q.output_script, dest) && IsValidDestination(dest)) {
            o.pushKV("address", EncodeDestination(dest));
        }
    }
    if (!q.claimant_key.empty()) o.pushKV("claimant", q.claimant_key);
    if (!q.refund_key.empty()) o.pushKV("refund_pubkey", q.refund_key);
    o.pushKV("automatic_spend", 0);
    o.pushKV("htlc", "htlc_sha256");
    o.pushKV("secrets", false);
    o.pushKV("wallet_seed", false);
    o.pushKV("service_sk", false);
    o.pushKV("use_claim", "buildhtlcclaim");
    o.pushKV("use_refund", "buildhtlcrefund");
    o.pushKV("note", "Public recovery material only. HASH160 htlc_tx is recovery-only and is not selected.");
    return o;
}

bool CreateUnsignedFunding(CWallet& wallet, FrozenFundingQuote& q, std::string& err)
{
    if (!ValidateFundingAmount(q.amount_atoms, err)) return false;
    if (q.output_script.empty() && !BuildHtlcSha256Descriptor(q, err)) return false;

    CTxDestination dest;
    if (!ExtractDestination(q.output_script, dest)) {
        dest = CNoDestination(q.output_script);
    }
    const std::vector<CRecipient> recipients{{dest, q.amount_atoms, /*fSubtractFeeFromAmount=*/false}};
    CCoinControl coin_control;
    wallet.BlockUntilSyncedToCurrentChain();
    LOCK(wallet.cs_wallet);
    auto res = CreateTransaction(wallet, recipients, /*change_pos=*/std::nullopt, coin_control, /*sign=*/false);
    if (!res) {
        err = util::ErrorString(res).original;
        return false;
    }
    if (q.fee_cap_atoms > 0 && res->fee > q.fee_cap_atoms) {
        err = strprintf("funding fee %d exceeds fee_cap_atoms %d", res->fee, q.fee_cap_atoms);
        return false;
    }
    q.fee_atoms = res->fee;
    q.unsigned_hex = EncodeHexTx(*res->tx);
    q.unsigned_txid = res->tx->GetHash().ToUint256();
    bool found = false;
    for (const auto& out : res->tx->vout) {
        if (out.scriptPubKey == q.output_script && out.nValue == q.amount_atoms) {
            found = true;
            break;
        }
    }
    if (!found) {
        err = "wallet funded transaction is missing the frozen HTLC output";
        return false;
    }
    return true;
}

bool SignFrozenFunding(CWallet& wallet, CMutableTransaction& mtx, bool& complete, std::string& err)
{
    EnsureWalletIsUnlocked(wallet);
    LOCK(wallet.cs_wallet);
    std::map<COutPoint, Coin> coins;
    for (const CTxIn& txin : mtx.vin) {
        coins[txin.prevout];
    }
    wallet.chain().findCoins(coins);
    std::map<int, bilingual_str> input_errors;
    complete = wallet.SignTransaction(mtx, coins, SIGHASH_DEFAULT, input_errors);
    if (!complete && !input_errors.empty()) {
        err = input_errors.begin()->second.original;
    }
    return true;
}

UniValue ObserveReleaseFunding(CWallet& wallet, const std::string& key_hash_hex, uint32_t refund_height,
                               const std::string& output_script_hex)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("confirmed_known", false);
    o.pushKV("confirmed_funded_atoms", 0);
    o.pushKV("pending_funded_atoms", 0);
    o.pushKV("wallet_contributor", false);
    o.pushKV("funding_source", "CHAIN_OBSERVATION");
    o.pushKV("helper_observation", false);
    o.pushKV("chain_observation", true);
    const std::string needle = ToLower(key_hash_hex);
    CScript want;
    if (!output_script_hex.empty() && IsHex(output_script_hex)) {
        const auto raw = ParseHex(ToLower(output_script_hex));
        want = CScript(raw.begin(), raw.end());
    }
    if (want.empty() && (needle.size() != 64 || !IsHex(needle))) {
        o.pushKV("note", "key_hash or output_script required to join chain UTXOs");
        return o;
    }
    int64_t confirmed = 0;
    int64_t pending = 0;
    bool contributor = false;
    std::string claim_txid;
    int tip = 0;
    {
        LOCK(wallet.cs_wallet);
        tip = wallet.GetLastBlockHeight();
        o.pushKV("chain_height", tip);
        o.pushKV("chain_height_known", true);
        for (const auto& [txid, wtx] : wallet.mapWallet) {
            if (!wtx.tx) continue;
            const int depth = wallet.GetTxDepthInMainChain(wtx);
            for (const auto& out : wtx.tx->vout) {
                bool match = false;
                if (!want.empty() && out.scriptPubKey == want) match = true;
                else if (want.empty() && needle.size() == 64 &&
                         ToLower(HexStr(out.scriptPubKey)).find(needle) != std::string::npos) {
                    match = true;
                }
                if (!match) continue;
                contributor = true;
                if (depth > 0) confirmed += out.nValue;
                else if (depth >= 0) pending += out.nValue;
            }
            for (const auto& in : wtx.tx->vin) {
                for (const auto& item : in.scriptWitness.stack) {
                    if (item.size() != 32) continue;
                    unsigned char digest[32];
                    CSHA256().Write(item.data(), item.size()).Finalize(digest);
                    if (needle.size() == 64 && ToLower(HexStr(Span<const unsigned char>{digest, 32})) == needle) {
                        contributor = true;
                        claim_txid = txid.GetHex();
                    }
                }
            }
        }
    }
    o.pushKV("confirmed_known", true);
    o.pushKV("confirmed_funded_atoms", confirmed);
    o.pushKV("pending_funded_atoms", pending);
    o.pushKV("wallet_contributor", contributor);
    const bool mature = refund_height > 0 && static_cast<uint32_t>(tip) >= refund_height;
    o.pushKV("refund_available_locally", contributor && mature && claim_txid.empty());
    if (!claim_txid.empty()) {
        o.pushKV("claim_txid", claim_txid);
        o.pushKV("refund_status", "CLAIM_COMPETING");
    } else if (refund_height == 0) {
        o.pushKV("refund_status", "UNKNOWN");
    } else if (!mature) {
        o.pushKV("refund_status", "NOT_MATURE");
    } else if (contributor) {
        o.pushKV("refund_status", "AVAILABLE");
    } else {
        o.pushKV("refund_status", "NOT_MATURE");
    }
    return o;
}

} // namespace wallet
