// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <wallet/rpc/bcp1.h>

#include <addresstype.h>
#include <chainparams.h>
#include <common/args.h>
#include <core_io.h>
#include <key_io.h>
#include <policy/feerate.h>
#include <pqkey.h>
#include <psbt.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/interpreter.h>
#include <script/pqm.h>
#include <script/signingprovider.h>
#include <streams.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/bcp1_deposit.h>
#include <wallet/bcp1_package.h>
#include <wallet/bcp1_watchonly.h>
#include <wallet/coincontrol.h>
#include <wallet/coinselection.h>
#include <wallet/rpc/util.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/signer_provider.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <limits>
#include <optional>
#include <string>
#include <vector>

namespace wallet {
namespace {

void ThrowIfPrivateSign(const CWallet& wallet)
{
    bilingual_str err;
    if (RefusePrivateSign(wallet, err)) {
        throw JSONRPCError(RPC_WALLET_ERROR, err.original);
    }
}

void ThrowIfWrongNetwork(const bcp1::Package& pkg)
{
    if (!pkg.network.empty() && pkg.network != Params().GetChainTypeString()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("BTXPSBT network '%s' does not match this node (%s)",
                                     pkg.network, Params().GetChainTypeString()));
    }
}

UniValue Unwrap(const UniValue& arg, const char* key)
{
    if (arg.isObject() && arg.exists(key) && !arg[key].isNull()) return arg[key];
    return arg;
}

std::string EncodePsbtBase64(const PartiallySignedTransaction& psbtx)
{
    DataStream ss{};
    ss << psbtx;
    return EncodeBase64(ss.str());
}

bcp1::Package PackageFromArg(const UniValue& raw)
{
    UniValue arg = Unwrap(raw, "package");
    bcp1::Package pkg;
    std::string error;
    if (arg.isObject()) {
        // Prefer BTXPSBT JSON. PackageResult also attaches a PSBT sidecar;
        // peeling that first dropped P2MR leaf/control and failed ValidateStructure.
        if (bcp1::Decode(arg, pkg, error)) {
            return pkg;
        }
        const std::string decode_err = error;
        if (arg.exists("psbt") && arg["psbt"].isStr()) {
            PartiallySignedTransaction psbt;
            std::string psbt_err;
            if (DecodeBase64PSBT(psbt, arg["psbt"].get_str(), psbt_err) &&
                bcp1::FromPSBT(psbt, Params().GetChainTypeString(), pkg, psbt_err)) {
                return pkg;
            }
        }
        throw JSONRPCError(RPC_INVALID_PARAMETER, decode_err.empty() ? "invalid BTXPSBT" : decode_err);
    }
    if (arg.isStr()) {
        PartiallySignedTransaction psbt;
        if (DecodeBase64PSBT(psbt, arg.get_str(), error)) {
            if (!bcp1::FromPSBT(psbt, Params().GetChainTypeString(), pkg, error)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, error);
            }
            return pkg;
        }
        CMutableTransaction mtx;
        if (DecodeHexTx(mtx, arg.get_str())) {
            if (!bcp1::FromUnsignedTx(mtx, {}, Params().GetChainTypeString(), pkg, error)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, error.empty() ? "unsigned hex missing prevouts" : error);
            }
            return pkg;
        }
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, error.empty() ? "package is not a PSBT, hex tx, or BTXPSBT" : error);
    }
    throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid BTXPSBT");
}

CAmount ParseAtomsOrAmount(const UniValue& o, const char* atoms_key, const char* amount_key)
{
    if (o.exists(atoms_key) && !o[atoms_key].isNull()) {
        if (o[atoms_key].isNum()) return o[atoms_key].getInt<int64_t>();
        int64_t v = 0;
        if (o[atoms_key].isStr() && ParseInt64(o[atoms_key].get_str(), &v)) return v;
    }
    if (o.exists(amount_key) && !o[amount_key].isNull()) return AmountFromValue(o[amount_key]);
    throw JSONRPCError(RPC_INVALID_PARAMETER, "amount or amount_atoms required");
}

std::vector<CRecipient> RecipientsFromValue(const UniValue& raw)
{
    UniValue arr = raw;
    if (arr.isObject() && arr.exists("outputs")) arr = arr["outputs"];
    else if (arr.isObject() && arr.exists("recipients")) arr = arr["recipients"];
    if (!arr.isArray()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "outputs must be an array of {address, amount}");
    }
    std::vector<CRecipient> recs;
    recs.reserve(arr.size());
    for (const UniValue& item : arr.getValues()) {
        if (item.isObject() && item.exists("address")) {
            const CTxDestination dest = DecodeDestination(item["address"].get_str());
            if (!IsValidDestination(dest)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "address");
            recs.push_back(CRecipient{dest, ParseAtomsOrAmount(item, "amount_atoms", "amount"), false});
            continue;
        }
        if (item.isObject()) {
            const auto keys = item.getKeys();
            if (keys.size() == 1) {
                const CTxDestination dest = DecodeDestination(keys[0]);
                if (!IsValidDestination(dest)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, keys[0]);
                recs.push_back(CRecipient{dest, AmountFromValue(item[keys[0]]), false});
                continue;
            }
        }
        throw JSONRPCError(RPC_INVALID_PARAMETER, "each output needs address and amount");
    }
    if (recs.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "outputs required");
    return recs;
}

UniValue PackageResult(const bcp1::Package& pkg)
{
    UniValue out = bcp1::Encode(pkg);
    UniValue selected(UniValue::VARR);
    UniValue outputs(UniValue::VARR);
    CAmount in_sum = 0;
    CAmount out_sum = 0;
    for (size_t i = 0; i < pkg.inputs.size(); ++i) {
        const auto& in = pkg.inputs[i];
        UniValue u(UniValue::VOBJ);
        u.pushKV("txid", in.txid.GetHex());
        u.pushKV("vout", static_cast<int64_t>(in.vout));
        if (in.amount >= 0) {
            u.pushKV("amount_atoms", in.amount);
            in_sum += in.amount;
        }
        selected.push_back(std::move(u));
    }
    for (size_t i = 0; i < pkg.unsigned_tx.vout.size(); ++i) {
        const CTxOut& txout = pkg.unsigned_tx.vout[i];
        UniValue o(UniValue::VOBJ);
        o.pushKV("n", static_cast<int64_t>(i));
        o.pushKV("amount_atoms", txout.nValue);
        o.pushKV("amount", ValueFromAmount(txout.nValue));
        CTxDestination dest;
        if (ExtractDestination(txout.scriptPubKey, dest)) {
            o.pushKV("address", EncodeDestination(dest));
        }
        outputs.push_back(std::move(o));
        out_sum += txout.nValue;
    }
    out.pushKV("selected_utxos", selected);
    out.pushKV("outputs", outputs);
    out.pushKV("recipients", outputs);
    if (!pkg.unsigned_tx.vin.empty() || !pkg.unsigned_tx.vout.empty()) {
        out.pushKV("unsigned_tx_hex", EncodeHexTx(CTransaction(pkg.unsigned_tx)));
    }
    if (in_sum >= out_sum && in_sum > 0) {
        out.pushKV("fee_atoms", in_sum - out_sum);
        out.pushKV("fee", ValueFromAmount(in_sum - out_sum));
    }
    out.pushKV("broadcast", false);
    out.pushKV("in_process_sign", false);
    return out;
}

bool ZmqEnabled()
{
#ifdef ENABLE_ZMQ
    return gArgs.IsArgSet("-zmqpubhashblock") || gArgs.IsArgSet("-zmqpubhashtx") ||
           gArgs.IsArgSet("-zmqpubrawblock") || gArgs.IsArgSet("-zmqpubrawtx") ||
           gArgs.IsArgSet("-zmqpubsequence") || gArgs.IsArgSet("-zmqpubhashwallettx");
#else
    return false;
#endif
}

UniValue ReadinessCapabilities(const Bcp1Readiness& r)
{
    UniValue caps(UniValue::VOBJ);
    caps.pushKV("descriptors_ok", r.descriptors_ok);
    caps.pushKV("watchonly_ok", r.watchonly_ok);
    caps.pushKV("synced_ok", r.synced_ok);
    caps.pushKV("deposits_ok", r.deposits_ok);
    caps.pushKV("signer_ok", r.signer_ok);
    caps.pushKV("pkcs11_live", r.pkcs11_live);
    caps.pushKV("kmip_live", r.kmip_live);
    caps.pushKV("https_live", r.https_live);
    // Aliases for callers that still use the pre-split names.
    caps.pushKV("descriptors", r.descriptors_ok);
    caps.pushKV("disable_private_keys", r.watchonly_ok);
    caps.pushKV("synced", r.synced_ok);
    caps.pushKV("deposit_pool", r.deposits_ok);
    caps.pushKV("signer_available", r.signer_ok);
    return caps;
}

std::string PoolLabel(uint32_t account, uint32_t branch, uint32_t index)
{
    const char* br = branch == bcp1::BRANCH_CHANGE ? "change" : "deposit";
    return strprintf("%u/%s/%u", account, br, index);
}

bool LabelMatchesPool(const std::string& label, uint32_t account, uint32_t branch, uint32_t index)
{
    if (label == PoolLabel(account, branch, index)) return true;
    // Legacy imports used deposit/<i> or change/<i> and omitted account.
    if (account == 0) {
        const std::string legacy = strprintf("%s/%u", branch == bcp1::BRANCH_CHANGE ? "change" : "deposit", index);
        if (label == legacy) return true;
    }
    if (account == 0 && branch == bcp1::BRANCH_DEPOSIT && index == 0 && label == "bcp1-deposit") return true;
    return false;
}

bool ParseUint32Index(int64_t v, uint32_t& out, const char* name, std::string& err)
{
    if (v < 0) {
        err = strprintf("%s cannot be negative", name);
        return false;
    }
    if (v > static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
        err = strprintf("%s exceeds uint32 range", name);
        return false;
    }
    out = static_cast<uint32_t>(v);
    return true;
}

std::string P2MRAddressFromWalletTree(Span<const unsigned char> ml, Span<const unsigned char> slh)
{
    if (!ml.empty() && !slh.empty()) return bcp1::EncodeP2MRFromPubkeys(ml, slh);
    if (!ml.empty()) return bcp1::EncodeP2MRFromPubkeys(ml, {});
    if (!slh.empty()) return bcp1::EncodeP2MRFromPubkeys({}, slh);
    return {};
}

CTxDestination WatchOmnibus(const CWallet& wallet);

void AttachWalletP2MR(const CWallet& wallet, bcp1::Package& pkg)
{
    AssertLockHeld(wallet.cs_wallet);
    for (bcp1::Input& in : pkg.inputs) {
        if (in.p2mr) continue;
        for (ScriptPubKeyMan* man : wallet.GetScriptPubKeyMans(in.script_pub_key)) {
            auto* dman = dynamic_cast<DescriptorScriptPubKeyMan*>(man);
            if (!dman) continue;
            auto provider = dman->GetP2MRSizingProvider(in.script_pub_key);
            if (!provider) continue;
            int wv = 0;
            std::vector<unsigned char> program;
            if (!in.script_pub_key.IsWitnessProgram(wv, program) || wv != 2 ||
                program.size() != WITNESS_V2_P2MR_SIZE) {
                continue;
            }
            P2MRSpendData spenddata;
            if (!provider->GetP2MRSpendData(WitnessV2P2MR{uint256(program)}, spenddata) ||
                spenddata.scripts.empty()) {
                continue;
            }
            std::vector<unsigned char> ml_pub;
            PQAlgorithm ml_algo = PQAlgorithm::ML_DSA_44;
            std::vector<unsigned char> slh_pub;
            PQAlgorithm slh_algo = PQAlgorithm::SLH_DSA_128S;
            const std::vector<unsigned char>* ml_leaf = nullptr;
            const std::vector<unsigned char>* ml_control = nullptr;
            const std::vector<unsigned char>* slh_leaf = nullptr;
            const std::vector<unsigned char>* slh_control = nullptr;
            for (const auto& [script, controls] : spenddata.scripts) {
                if (script.empty() || controls.empty()) continue;
                PQAlgorithm leaf_algo;
                std::vector<unsigned char> leaf_pk;
                if (!ExtractP2MRChecksigPubkey(script, leaf_algo, leaf_pk)) continue;
                if (leaf_algo == PQAlgorithm::ML_DSA_44 && !ml_leaf) {
                    ml_pub = std::move(leaf_pk);
                    ml_algo = leaf_algo;
                    ml_leaf = &script;
                    ml_control = &*controls.begin();
                } else if (leaf_algo == PQAlgorithm::SLH_DSA_128S && !slh_leaf) {
                    slh_pub = std::move(leaf_pk);
                    slh_algo = leaf_algo;
                    slh_leaf = &script;
                    slh_control = &*controls.begin();
                }
            }
            const std::vector<unsigned char>* leaf = ml_leaf ? ml_leaf : slh_leaf;
            const std::vector<unsigned char>* control = ml_leaf ? ml_control : slh_control;
            if (!leaf || !control) {
                for (const auto& [script, controls] : spenddata.scripts) {
                    if (script.empty() || controls.empty()) continue;
                    leaf = &script;
                    control = &*controls.begin();
                    break;
                }
            }
            if (!leaf || !control) continue;
            bcp1::P2MRSpend spend;
            spend.leaf_script = *leaf;
            spend.control_block = *control;
            spend.leaf_version = static_cast<uint8_t>(spend.control_block[0] & P2MR_LEAF_MASK);
            in.p2mr = std::move(spend);
            if (!ml_pub.empty()) {
                in.pubkey = ml_pub;
                in.algo = ml_algo;
            } else if (!slh_pub.empty()) {
                in.pubkey = slh_pub;
                in.algo = slh_algo;
            }
            break;
        }
    }
}

CCoinControl CoinControlFromOptions(const CWallet& wallet, const UniValue& options, int default_minconf = 0)
{
    CCoinControl cc;
    cc.fAllowWatchOnly = ParseIncludeWatchonly(NullUniValue, wallet);
    cc.m_min_depth = default_minconf;
    const UniValue& minconf = options.exists("minconf") ? options["minconf"] :
                              options.exists("min_confirmations") ? options["min_confirmations"] : NullUniValue;
    if (!minconf.isNull()) {
        const int v = minconf.getInt<int>();
        if (v < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "minconf cannot be negative");
        cc.m_min_depth = v;
    }
    const UniValue& maxconf = options.exists("maxconf") ? options["maxconf"] :
                              options.exists("max_confirmations") ? options["max_confirmations"] : NullUniValue;
    if (!maxconf.isNull()) {
        const int v = maxconf.getInt<int>();
        if (v < cc.m_min_depth) throw JSONRPCError(RPC_INVALID_PARAMETER, "maxconf cannot be lower than minconf");
        cc.m_max_depth = v;
    }
    if (options.exists("include_unsafe") && options["include_unsafe"].get_bool()) {
        cc.m_include_unsafe_inputs = true;
    }
    if (options.exists("fee_rate")) {
        cc.m_feerate = CFeeRate{AmountFromValue(options["fee_rate"], /*decimals=*/3)};
        cc.fOverrideFeeRate = true;
    }
    if (options.exists("change_address") && options["change_address"].isStr()) {
        const CTxDestination dest = DecodeDestination(options["change_address"].get_str());
        if (!IsValidDestination(dest)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "change_address");
        cc.destChange = dest;
    }
    return cc;
}

UniValue FundedPackage(CWallet& wallet, const std::vector<CRecipient>& recipients, CCoinControl coin_control,
                       std::optional<unsigned int> change_pos)
{
    LOCK(wallet.cs_wallet);
    coin_control.fAllowWatchOnly = ParseIncludeWatchonly(NullUniValue, wallet);
    if (wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        coin_control.fAllowWatchOnly = true;
        if (!IsValidDestination(coin_control.destChange)) {
            try {
                coin_control.destChange = WatchOmnibus(wallet);
            } catch (const UniValue&) {
                // No imported pool label yet; CreateTransaction may still use a signer keypool.
            }
        }
    }
    auto res = CreateTransaction(wallet, recipients, change_pos, coin_control, /*sign=*/false);
    if (!res) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(res).original);
    }
    PartiallySignedTransaction psbtx{CMutableTransaction(*res->tx)};
    bool complete = false;
    if (const auto err = wallet.FillPSBT(psbtx, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "FillPSBT failed");
    }
    bcp1::Package pkg;
    std::string error;
    if (!bcp1::FromPSBT(psbtx, Params().GetChainTypeString(), pkg, error)) {
        std::vector<CTxOut> prevouts;
        CMutableTransaction mtx(*res->tx);
        prevouts.reserve(mtx.vin.size());
        for (const CTxIn& vin : mtx.vin) {
            const CWalletTx* wtx = wallet.GetWalletTx(vin.prevout.hash.ToUint256());
            if (!wtx || vin.prevout.n >= wtx->tx->vout.size()) {
                throw JSONRPCError(RPC_WALLET_ERROR, error.empty() ? "missing prevout for unsigned package" : error);
            }
            prevouts.push_back(wtx->tx->vout[vin.prevout.n]);
        }
        if (!bcp1::FromUnsignedTx(mtx, prevouts, Params().GetChainTypeString(), pkg, error)) {
            throw JSONRPCError(RPC_WALLET_ERROR, error.empty() ? "unsigned package" : error);
        }
    }
    AttachWalletP2MR(wallet, pkg);
    if (!bcp1::FillCanonicalDigests(pkg, error)) {
        throw JSONRPCError(RPC_WALLET_ERROR, error.empty() ? "canonical P2MR digest" : error);
    }
    UniValue out = PackageResult(pkg);
    out.pushKV("psbt", EncodePsbtBase64(psbtx));
    out.pushKV("fee_atoms", res->fee);
    out.pushKV("fee", ValueFromAmount(res->fee));
    out.pushKV("change_pos", res->change_pos ? static_cast<int>(*res->change_pos) : -1);
    out.pushKV("complete", complete);
    out.pushKV("broadcast", false);
    return out;
}

CTxDestination WatchOmnibus(const CWallet& wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    std::optional<CTxDestination> deposit0;
    std::optional<CTxDestination> any;
    for (const auto& [dest, entry] : wallet.m_address_book) {
        if (!IsValidDestination(dest)) continue;
        const std::string label = entry.GetLabel();
        if (label == "change/0") return dest;
        if (label == "deposit/0" || label == "bcp1-deposit") {
            if (!deposit0) deposit0 = dest;
        }
        if (!any) any = dest;
    }
    if (deposit0) return *deposit0;
    if (any) return *any;
    throw JSONRPCError(RPC_INVALID_PARAMETER, "change_address required for watch-only consolidation");
}

UniValue NormalizePlanOptions(UniValue options)
{
    if (options.isNull()) options = UniValue(UniValue::VOBJ);
    if (options.exists("plan") && options["plan"].isObject()) {
        const UniValue plan = options["plan"];
        for (const std::string& k : plan.getKeys()) {
            if (!options.exists(k)) options.pushKV(k, plan[k]);
        }
    }
    if (options.exists("min_confirmations") && !options.exists("minconf")) {
        options.pushKV("minconf", options["min_confirmations"]);
    }
    return options;
}

bool SelectPlanInputs(CCoinControl& cc, const UniValue& options)
{
    const UniValue* ins = nullptr;
    if (options.exists("inputs") && options["inputs"].isArray() && !options["inputs"].empty()) {
        ins = &options["inputs"];
    } else if (options.exists("selected_utxos") && options["selected_utxos"].isArray() && !options["selected_utxos"].empty()) {
        ins = &options["selected_utxos"];
    }
    if (!ins) return false;
    for (const UniValue& i : ins->getValues()) {
        if (!i.isObject() || !i.exists("txid")) continue;
        const uint256 txid = ParseHashV(i["txid"], "txid");
        const int64_t vout = i.exists("vout") ? i["vout"].getInt<int64_t>() : 0;
        if (vout < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "vout cannot be negative");
        cc.Select(COutPoint(Txid::FromUint256(txid), static_cast<uint32_t>(vout)));
    }
    cc.m_allow_other_inputs = false;
    return cc.HasSelected();
}

UniValue PlanCoins(CWallet& wallet, UniValue options, bool create_tx)
{
    options = NormalizePlanOptions(std::move(options));
    LOCK(wallet.cs_wallet);
    CoinFilterParams fp;
    fp.only_spendable = false;
    CCoinControl cc = CoinControlFromOptions(wallet, options, /*default_minconf=*/1);
    if (options.exists("minimum_input_value")) fp.min_amount = AmountFromValue(options["minimum_input_value"]);
    if (options.exists("min_input_value")) fp.min_amount = AmountFromValue(options["min_input_value"]);
    if (options.exists("minimumAmount")) fp.min_amount = AmountFromValue(options["minimumAmount"]);
    if (options.exists("min_amount")) fp.min_amount = AmountFromValue(options["min_amount"]);
    const bool have_plan_inputs = SelectPlanInputs(cc, options);
    auto coins = AvailableCoinsListUnspent(wallet, &cc, fp);
    std::vector<COutput> all = coins.All();
    const size_t max_inputs = options.exists("max_inputs") ? static_cast<size_t>(options["max_inputs"].getInt<int64_t>()) :
                              options.exists("batch_size") ? static_cast<size_t>(options["batch_size"].getInt<int64_t>()) :
                              all.size();
    const size_t target = options.exists("target_utxo_count") ? static_cast<size_t>(options["target_utxo_count"].getInt<int64_t>()) : 1;
    CAmount fee_ceiling = MAX_MONEY;
    if (options.exists("fee_ceiling")) fee_ceiling = AmountFromValue(options["fee_ceiling"]);
    else if (options.exists("fee_ceiling_atoms") && options["fee_ceiling_atoms"].isNum()) {
        fee_ceiling = options["fee_ceiling_atoms"].getInt<int64_t>();
    }
    std::vector<COutput> selected;
    if (!have_plan_inputs) {
        for (const COutput& c : all) {
            if (selected.size() >= max_inputs) break;
            selected.push_back(c);
            if (all.size() - selected.size() <= target && !selected.empty()) break;
        }
        for (const COutput& c : selected) cc.Select(c.outpoint);
        cc.m_allow_other_inputs = false;
    } else {
        for (const COutput& c : all) {
            if (cc.IsSelected(c.outpoint)) selected.push_back(c);
        }
    }
    UniValue plan(UniValue::VOBJ);
    UniValue ins(UniValue::VARR);
    CAmount total = 0;
    for (const COutput& c : selected) {
        UniValue i(UniValue::VOBJ);
        i.pushKV("txid", c.outpoint.hash.GetHex());
        i.pushKV("vout", static_cast<int>(c.outpoint.n));
        i.pushKV("amount_atoms", c.txout.nValue);
        i.pushKV("amount", ValueFromAmount(c.txout.nValue));
        i.pushKV("confirmations", c.depth);
        CTxDestination dest;
        if (ExtractDestination(c.txout.scriptPubKey, dest)) {
            i.pushKV("address", EncodeDestination(dest));
        }
        ins.push_back(i);
        total += c.txout.nValue;
    }
    plan.pushKV("inputs", ins);
    plan.pushKV("selected_utxos", ins);
    plan.pushKV("input_count", static_cast<int>(selected.size()));
    plan.pushKV("available_utxos", static_cast<int>(all.size()));
    plan.pushKV("total_atoms", total);
    plan.pushKV("selected_sum", ValueFromAmount(total));
    plan.pushKV("fee_ceiling_atoms", fee_ceiling);
    plan.pushKV("would_broadcast", false);
    if (!create_tx) {
        return plan;
    }
    if (selected.empty()) throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "no deposit UTXOs");
    CTxDestination change = CNoDestination();
    if (options.exists("change_address") && options["change_address"].isStr()) {
        change = DecodeDestination(options["change_address"].get_str());
        if (!IsValidDestination(change)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "change_address");
    } else if (options.exists("destination") && options["destination"].isStr()) {
        change = DecodeDestination(options["destination"].get_str());
        if (!IsValidDestination(change)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "destination");
    } else {
        change = WatchOmnibus(wallet);
    }
    cc.destChange = change;
    std::vector<CRecipient> rec{{change, total, /*fSubtractFeeFromAmount=*/true}};
    UniValue funded = FundedPackage(wallet, rec, cc, /*change_pos=*/0);
    if (funded.exists("fee_atoms") && funded["fee_atoms"].getInt<int64_t>() > fee_ceiling) {
        throw JSONRPCError(RPC_WALLET_ERROR, "estimated fee exceeds fee_ceiling");
    }
    return funded;
}

bool InsertExternalSig(bcp1::Package& pkg, size_t fallback_index, const UniValue& sig_item, std::string& error)
{
    if (sig_item.isStr()) {
        if (!IsHex(sig_item.get_str())) {
            error = "signature must be hex";
            return false;
        }
        return bcp1::InsertSignature(pkg, fallback_index, ParseHex(sig_item.get_str()), error);
    }
    if (!sig_item.isObject()) {
        error = "signature must be hex or {vin, pubkey, signature}";
        return false;
    }
    size_t vin = fallback_index;
    const UniValue& vin_v = sig_item.exists("vin") ? sig_item["vin"] :
                            sig_item.exists("index") ? sig_item["index"] : NullUniValue;
    if (!vin_v.isNull()) {
        const int64_t v = vin_v.getInt<int64_t>();
        if (v < 0) {
            error = "vin out of range";
            return false;
        }
        vin = static_cast<size_t>(v);
    }
    if (!sig_item.exists("signature") || !sig_item["signature"].isStr() || !IsHex(sig_item["signature"].get_str())) {
        error = "signature hex required";
        return false;
    }
    const auto signature = ParseHex(sig_item["signature"].get_str());
    if (sig_item.exists("pubkey") && sig_item["pubkey"].isStr()) {
        if (!IsHex(sig_item["pubkey"].get_str())) {
            error = "pubkey must be hex";
            return false;
        }
        return bcp1::InsertSignature(pkg, vin, ParseHex(sig_item["pubkey"].get_str()), signature, error);
    }
    return bcp1::InsertSignature(pkg, vin, signature, error);
}

UniValue ImportArg(const UniValue& raw)
{
    if (raw.isObject() && raw.exists("entries")) return raw["entries"];
    return raw;
}

} // namespace

bool IsBcp1WatchOnly(const CWallet& wallet)
{
    return ExchangeWatchOnlyActive(wallet);
}

bool NodeExchangeWatchOnly()
{
    return ExchangeWatchOnlyNodeEnabled(gArgs);
}

RPCHelpMan getexchangereadiness()
{
    return RPCHelpMan{
        "getexchangereadiness",
        "BCP/1 monetary custody readiness. Never requires Model Network, HCP, GPU, or in-process keys.\n"
        "ML-DSA-44 cannot do Bitcoin-style public child derivation; deposit addresses come from importdepositpool or signer GetPublicKey.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "BCP/1 fields"},
            {RPCResult::Type::STR, "profile", "BTX_EXCHANGE_PROFILE_V1"},
            {RPCResult::Type::STR, "network", "Chain type string"},
            {RPCResult::Type::BOOL, "watch_only", "disable_private_keys and/or -exchange-watchonly"},
            {RPCResult::Type::BOOL, "public_child_derivation", "Always false for ML-DSA-44"},
            {RPCResult::Type::BOOL, "descriptors_ok", "WALLET_FLAG_DESCRIPTORS"},
            {RPCResult::Type::BOOL, "watchonly_ok", "disable_private_keys and no embedded PQ seeds"},
            {RPCResult::Type::BOOL, "synced_ok", "Node is not in initial block download"},
            {RPCResult::Type::BOOL, "deposits_ok", "Imported P2MR deposit-pool material is present"},
            {RPCResult::Type::BOOL, "signer_ok", "Healthy command -signer (never PKCS#11/KMIP/HTTPS)"},
            {RPCResult::Type::BOOL, "pkcs11_live", "Always false: PKCS#11 adapter is an unlinked stub"},
            {RPCResult::Type::BOOL, "kmip_live", "Always false: KMIP adapter is an unlinked stub"},
            {RPCResult::Type::BOOL, "https_live", "Always false: HTTPS adapter is an unlinked stub"},
            {RPCResult::Type::BOOL, "ready", "descriptors_ok && watchonly_ok && synced_ok && (deposits_ok || signer_ok) && !pkcs11_live && !kmip_live && !https_live"},
            {RPCResult::Type::OBJ, "ready_capabilities", "Split readiness bits", {
                {RPCResult::Type::BOOL, "descriptors_ok", "WALLET_FLAG_DESCRIPTORS"},
                {RPCResult::Type::BOOL, "watchonly_ok", "disable_private_keys and no PQ seeds"},
                {RPCResult::Type::BOOL, "synced_ok", "Not IBD"},
                {RPCResult::Type::BOOL, "deposits_ok", "Deposit pool material"},
                {RPCResult::Type::BOOL, "signer_ok", "Healthy command -signer"},
                {RPCResult::Type::BOOL, "pkcs11_live", "Always false"},
                {RPCResult::Type::BOOL, "kmip_live", "Always false"},
                {RPCResult::Type::BOOL, "https_live", "Always false"},
                {RPCResult::Type::ELISION, "", "aliases and extra bits"},
            }},
            {RPCResult::Type::ELISION, "", "additional BCP/1 readiness fields"},
        }},
        RPCExamples{HelpExampleCli("getexchangereadiness", "") + HelpExampleRpc("getexchangereadiness", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            (void)self;
            UniValue o(UniValue::VOBJ);
            o.pushKV("profile", bcp1::PROFILE_ID);
            o.pushKV("custody_profile", "BCP/1");
            o.pushKV("chain", bcp1::CHAIN_ID);
            o.pushKV("network", Params().GetChainTypeString());
            o.pushKV("walletname", pwallet->GetName());
            o.pushKV("descriptors", pwallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));
            o.pushKV("disable_private_keys", pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));
            o.pushKV("private_keys_enabled", !pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));
            o.pushKV("external_signer", pwallet->IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER));
            o.pushKV("watch_only", IsBcp1WatchOnly(*pwallet));
            o.pushKV("exchange_watchonly", NodeExchangeWatchOnly() || ExchangeWatchOnlyActive(*pwallet));
            o.pushKV("public_child_derivation", false);
            o.pushKV("derivation_path", strprintf("m/%uh/%uh/<account>h/<branch>/<index>",
                                                  bcp1::PURPOSE, Params().IsTestChain() ? 1 : 0));
            {
                LOCK(pwallet->cs_wallet);
                o.pushKV("blocks", pwallet->GetLastBlockHeight());
                o.pushKV("bestblockhash", pwallet->GetLastBlockHash().GetHex());
            }
            o.pushKV("initialblockdownload", pwallet->chain().isInitialBlockDownload());
            o.pushKV("txindex", gArgs.GetBoolArg("-txindex", false));
            o.pushKV("zmq", ZmqEnabled());
#ifdef ENABLE_MODELNET
            o.pushKV("modelnet_compiled", true);
#else
            o.pushKV("modelnet_compiled", false);
#endif
            o.pushKV("model_network_required", false);
            o.pushKV("hcp_required", false);
            o.pushKV("gpu_required", false);
            o.pushKV("automatic_spend_atoms", 0);
            // In-process signing is a wallet-flag fact, not a BCP/1 profile fact.
            // A disable_private_keys wallet (with or without -exchange-watchonly)
            // has no in-process keys; do not report true merely because the
            // node never opted into BCP/1.
            o.pushKV("can_sign_in_process", !pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));
            const Bcp1Readiness readiness = EvaluateBcp1Readiness(*pwallet, gArgs);
            o.pushKV("descriptors_ok", readiness.descriptors_ok);
            o.pushKV("watchonly_ok", readiness.watchonly_ok);
            o.pushKV("synced_ok", readiness.synced_ok);
            o.pushKV("deposits_ok", readiness.deposits_ok);
            o.pushKV("signer_ok", readiness.signer_ok);
            o.pushKV("pkcs11_live", readiness.pkcs11_live);
            o.pushKV("kmip_live", readiness.kmip_live);
            o.pushKV("https_live", readiness.https_live);
            UniValue caps = ReadinessCapabilities(readiness);
            caps.pushKV("external_signer", pwallet->IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER));
            o.pushKV("ready_capabilities", std::move(caps));
            o.pushKV("ready", readiness.Ready());
            o.pushKV("signer_configured", !gArgs.GetArg("-signer", "").empty());
            o.pushKV("signer", readiness.signer_health);
            return o;
        },
    };
}

RPCHelpMan deriveexchangeaddress()
{
    return RPCHelpMan{
        "deriveexchangeaddress",
        "Return a watch-only deposit (branch 0) or change (branch 1) address at index from the imported pool or signer GetPublicKey.\n"
        "ML-DSA public children are unsupported; this RPC never derives from a seed or xpub.\n",
        {
            {"index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Deposit index", RPCArgOptions{.skip_type_check = true}},
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "", {
                {"branch", RPCArg::Type::NUM, RPCArg::Default{0}, "0 = deposit, 1 = change"},
                {"account", RPCArg::Type::NUM, RPCArg::Default{0}, "Account index"},
                {"algorithm", RPCArg::Type::STR, RPCArg::Default{"ML-DSA-44"}, "ml_dsa_44 / ML-DSA-44 or slh_dsa_128s"},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "BCP/1 fields"},
            {RPCResult::Type::STR, "address", "P2MR address"},
            {RPCResult::Type::NUM, "index", "Requested index"},
            {RPCResult::Type::BOOL, "public_child_derivation", "false"},
            {RPCResult::Type::ELISION, "", "path / algorithm / pool metadata"},
        }},
        RPCExamples{HelpExampleCli("deriveexchangeaddress", "0")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            (void)self;
            UniValue first = request.params[0];
            UniValue opt = request.params[1].isNull() ? UniValue(UniValue::VOBJ) : request.params[1];
            if (first.isObject()) {
                if (opt.empty()) opt = first;
                else {
                    for (const std::string& k : first.getKeys()) {
                        if (!opt.exists(k)) opt.pushKV(k, first[k]);
                    }
                }
            }
            int64_t index64 = -1;
            if (first.isNum()) index64 = first.getInt<int64_t>();
            else if (opt.exists("index")) index64 = opt["index"].getInt<int64_t>();
            uint32_t index = 0;
            std::string idx_err;
            if (!ParseUint32Index(index64, index, "index", idx_err)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, idx_err);
            }
            uint32_t branch = bcp1::BRANCH_DEPOSIT;
            uint32_t account = 0;
            PQAlgorithm algo = PQAlgorithm::ML_DSA_44;
            if (opt.exists("branch")) {
                const int b = opt["branch"].getInt<int>();
                if (b != 0 && b != 1) throw JSONRPCError(RPC_INVALID_PARAMETER, "branch must be 0 or 1");
                branch = static_cast<uint32_t>(b);
            }
            if (opt.exists("account")) {
                std::string acc_err;
                if (!ParseUint32Index(opt["account"].getInt<int64_t>(), account, "account", acc_err)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, acc_err);
                }
            }
            if (opt.exists("algorithm") && !bcp1::ParseAlgo(opt["algorithm"].get_str(), algo)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown algorithm");
            }
            const std::string want = PoolLabel(account, branch, index);
            const std::string path = strprintf("m/87h/%uh/%uh/%u/%u",
                                               Params().IsTestChain() ? 1 : 0, account, branch, index);
            {
                LOCK(pwallet->cs_wallet);
                for (const auto& [dest, entry] : pwallet->m_address_book) {
                    const std::string label = entry.GetLabel();
                    if (LabelMatchesPool(label, account, branch, index) || label == want) {
                        UniValue o(UniValue::VOBJ);
                        o.pushKV("address", EncodeDestination(dest));
                        o.pushKV("index", static_cast<int64_t>(index));
                        o.pushKV("branch", static_cast<int64_t>(branch));
                        o.pushKV("account", static_cast<int64_t>(account));
                        o.pushKV("path", path);
                        o.pushKV("public_child_derivation", false);
                        o.pushKV("source", "pool");
                        return o;
                    }
                }
            }
            const std::string cmd = gArgs.GetArg("-signer", "");
            if (!cmd.empty()) {
                std::string error;
                auto signer = MakeCommandSigner(cmd, Params().GetChainTypeString(), std::nullopt, error);
                if (!signer) {
                    throw JSONRPCError(RPC_WALLET_ERROR, error.empty() ? "signer unavailable" : error);
                }
                std::vector<unsigned char> ml_pub;
                std::vector<unsigned char> slh_pub;
                if (!signer->GetPublicKey(path, PQAlgorithm::ML_DSA_44, ml_pub, error)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, error);
                }
                std::string slh_err;
                (void)signer->GetPublicKey(path, PQAlgorithm::SLH_DSA_128S, slh_pub, slh_err);
                UniValue o(UniValue::VOBJ);
                o.pushKV("address", P2MRAddressFromWalletTree(ml_pub, slh_pub));
                o.pushKV("pubkey", HexStr(ml_pub));
                if (!slh_pub.empty()) o.pushKV("pubkey_slh", HexStr(slh_pub));
                o.pushKV("index", static_cast<int64_t>(index));
                o.pushKV("branch", static_cast<int64_t>(branch));
                o.pushKV("path", path);
                o.pushKV("algorithm", bcp1::FormatAlgo(algo));
                o.pushKV("public_child_derivation", false);
                o.pushKV("source", "signer");
                o.pushKV("tree", slh_pub.empty() ? "single_leaf" : "ml_slh");
                return o;
            }
            throw JSONRPCError(RPC_WALLET_ERROR,
                               "No imported pool entry for that index. Use importdepositpool or a signer GetPublicKey. "
                               "ML-DSA-44 cannot derive public children.");
        },
    };
}

RPCHelpMan importdepositpool()
{
    return RPCHelpMan{
        "importdepositpool",
        "Import a pre-generated P2MR address/pubkey pool. Refuses private keys and PQ seeds.\n",
        {
            {"entries", RPCArg::Type::ARR, RPCArg::Optional::NO, "Addresses, pubkeys, or objects", {
                {"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "P2MR address or pubkey hex"},
                {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "", {
                    {"index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Address index"},
                    {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "P2MR address"},
                    {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Watch-only ML-DSA-44 pubkey"},
                    {"pubkey_slh", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Watch-only SLH-DSA-128s pubkey (default 2-leaf wallet tree)"},
                    {"label", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Address-book label (default <account>/deposit|change/<index>)"},
                    {"branch", RPCArg::Type::NUM, RPCArg::Default{0}, "0 deposit / 1 change"},
                }},
            }, RPCArgOptions{.skip_type_check = true}},
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "", {
                {"rescan", RPCArg::Type::BOOL, RPCArg::Default{false}, "Rescan after import"},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "BCP/1 fields"},
            {RPCResult::Type::BOOL, "success", "true if imported"},
            {RPCResult::Type::NUM, "imported", "Number of descriptors added"},
            {RPCResult::Type::BOOL, "solvable", "false when any entry was address-only (addr()) and cannot fill signing digests"},
            {RPCResult::Type::BOOL, "address_only", "true when any entry was address-only"},
            {RPCResult::Type::BOOL, "public_child_derivation", "Always false"},
            {RPCResult::Type::BOOL, "rescan", "Whether a rescan ran"},
            {RPCResult::Type::ELISION, "", "warnings"},
        }},
        RPCExamples{HelpExampleCli("importdepositpool", "'[\"btxrt1z...\"]'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            (void)self;
            bilingual_str err;
            UniValue details(UniValue::VOBJ);
            if (!ImportDepositPool(*pwallet, ImportArg(request.params[0]), err, details)) {
                throw JSONRPCError(RPC_WALLET_ERROR, err.original);
            }
            bool rescan = false;
            if (!request.params[1].isNull() && request.params[1].isObject() && request.params[1].exists("rescan")) {
                rescan = request.params[1]["rescan"].get_bool();
            }
            if (rescan) {
                WalletRescanReserver reserver(*pwallet);
                if (!reserver.reserve()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning");
                }
                pwallet->RescanFromTime(0, reserver, true);
            }
            UniValue o(UniValue::VOBJ);
            o.pushKV("success", true);
            o.pushKV("public_child_derivation", false);
            o.pushKV("rescan", rescan);
            if (details.exists("imported")) o.pushKV("imported", details["imported"]);
            if (details.exists("solvable")) o.pushKV("solvable", details["solvable"]);
            if (details.exists("address_only")) o.pushKV("address_only", details["address_only"]);
            if (details.exists("warning")) o.pushKV("warning", details["warning"]);
            return o;
        },
    };
}

RPCHelpMan prepareexternalsign()
{
    return RPCHelpMan{
        "prepareexternalsign",
        "Attach canonical P2MR signing digests to a BTXPSBT or PSBT. Does not sign with wallet keys. Does not broadcast.\n",
        {
            {"package", RPCArg::Type::OBJ, RPCArg::Optional::NO, "BTXPSBT object, base64 PSBT, unsigned hex, or {recipients|outputs|psbt}", {}, RPCArgOptions{.skip_type_check = true}},
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "", {
                {"sign", RPCArg::Type::BOOL, RPCArg::Default{false}, "Must remain false. Watch-only / -exchange-watchonly refuse in-process sign."},
                {"change_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Change destination when funding from recipients"},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "BCP/1 fields"},
            {RPCResult::Type::STR, "format", "BTXPSBT"},
            {RPCResult::Type::ARR, "digests", "Per-input canonical digests", {
                {RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "BCP/1 fields"},
                    {RPCResult::Type::NUM, "index", "Input index"},
                    {RPCResult::Type::STR_HEX, "digest", /*optional=*/true, "32-byte sighash"},
                    {RPCResult::Type::ELISION, "", "path / pubkey / algo"},
                }},
            }},
            {RPCResult::Type::BOOL, "broadcast", "Always false"},
            {RPCResult::Type::ELISION, "", "BTXPSBT fields (inputs, unsigned_tx_hex, fee)"},
        }},
        RPCExamples{HelpExampleCli("prepareexternalsign", "'{\"format\":\"BTXPSBT\",...}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            (void)self;
            if (!request.params[1].isNull() && request.params[1].exists("sign") && request.params[1]["sign"].get_bool()) {
                ThrowIfPrivateSign(*pwallet);
                throw JSONRPCError(RPC_WALLET_ERROR, "prepareexternalsign does not sign with wallet keys");
            }
            const UniValue& arg = request.params[0];
            if (arg.isObject() && (arg.exists("recipients") || arg.exists("outputs"))) {
                pwallet->BlockUntilSyncedToCurrentChain();
                UniValue options = request.params[1].isNull() ? UniValue(UniValue::VOBJ) : request.params[1];
                if (arg.exists("change_address") && !options.exists("change_address")) {
                    options.pushKV("change_address", arg["change_address"]);
                }
                CCoinControl cc = CoinControlFromOptions(*pwallet, options, /*default_minconf=*/1);
                return FundedPackage(*pwallet, RecipientsFromValue(arg), cc, std::nullopt);
            }
            bcp1::Package pkg = PackageFromArg(arg);
            ThrowIfWrongNetwork(pkg);
            std::string error;
            if (!bcp1::FillCanonicalDigests(pkg, error)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, error);
            }
            return PackageResult(pkg);
        },
    };
}

RPCHelpMan getsigningdigests()
{
    return RPCHelpMan{
        "getsigningdigests",
        "Return canonical per-input P2MR digests for a BTXPSBT package. Does not sign. No secrets.\n",
        {{"package", RPCArg::Type::OBJ, RPCArg::Optional::NO, "BTXPSBT, base64 PSBT, unsigned hex, or {package:...}", {}, RPCArgOptions{.skip_type_check = true}}},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "BCP/1 fields"},
            {RPCResult::Type::ARR, "digests", "", {{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "BCP/1 fields"},
                {RPCResult::Type::NUM, "index", ""},
                {RPCResult::Type::STR_HEX, "digest", /*optional=*/true, ""},
                {RPCResult::Type::ELISION, "", "path / pubkey / algo"},
            }}}},
            {RPCResult::Type::ELISION, "", "package echo"},
        }},
        RPCExamples{HelpExampleCli("getsigningdigests", "'{...}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            (void)self;
            (void)pwallet;
            bcp1::Package pkg = PackageFromArg(request.params[0]);
            ThrowIfWrongNetwork(pkg);
            std::string error;
            if (!bcp1::FillCanonicalDigests(pkg, error)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, error);
            }
            UniValue encoded = bcp1::Encode(pkg);
            UniValue o(UniValue::VOBJ);
            o.pushKV("profile", bcp1::PROFILE_ID);
            o.pushKV("network", pkg.network);
            o.pushKV("digests", encoded["digests"]);
            o.pushKV("package", encoded);
            return o;
        },
    };
}

RPCHelpMan finalizeexternalsign()
{
    return RPCHelpMan{
        "finalizeexternalsign",
        "Insert external signatures into a BTXPSBT, verify them against the canonical digest and prevout, and return hex.\n"
        "Rejects corrupt ML-DSA signatures and wrong prevouts. Never signs with wallet keys. Never broadcasts.\n",
        {
            {"package", RPCArg::Type::OBJ, RPCArg::Optional::NO, "BTXPSBT", {}, RPCArgOptions{.skip_type_check = true}},
            {"signatures", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Hex signatures or {vin|index, pubkey, signature} objects", {
                {"signature", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "ML-DSA or SLH-DSA signature"},
                {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "", {
                    {"vin", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Input index (default: array position)"},
                    {"index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Alias of vin"},
                    {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "PQ public key"},
                    {"signature", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "PQ signature"},
                    {"algorithm", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "ML-DSA-44 / ml_dsa_44"},
                }},
            }, RPCArgOptions{.skip_type_check = true}},
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "", {
                {"sign", RPCArg::Type::BOOL, RPCArg::Default{false}, "Must remain false."},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "BCP/1 fields"},
            {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "Serialized transaction if complete"},
            {RPCResult::Type::BOOL, "complete", "All inputs have valid signatures"},
            {RPCResult::Type::BOOL, "broadcast", "Always false"},
            {RPCResult::Type::ELISION, "", "txid / signatures_attached / error"},
        }},
        RPCExamples{HelpExampleCli("finalizeexternalsign", "'{...}' '[\"ab...\"]'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            (void)self;
            if (!request.params[2].isNull() && request.params[2].exists("sign") && request.params[2]["sign"].get_bool()) {
                ThrowIfPrivateSign(*pwallet);
                throw JSONRPCError(RPC_WALLET_ERROR, "finalizeexternalsign only attaches external signatures");
            }
            UniValue pkg_arg = request.params[0];
            UniValue sigs = request.params[1];
            if (pkg_arg.isObject() && pkg_arg.exists("package")) {
                if ((sigs.isNull() || !sigs.isArray()) && pkg_arg.exists("signatures")) sigs = pkg_arg["signatures"];
                pkg_arg = pkg_arg["package"];
            }
            if ((sigs.isNull() || !sigs.isArray()) && pkg_arg.isObject() && pkg_arg.exists("signatures")) {
                sigs = pkg_arg["signatures"];
            }
            if ((sigs.isNull() || !sigs.isArray()) && !request.params[2].isNull() && request.params[2].exists("signatures")) {
                sigs = request.params[2]["signatures"];
            }
            bcp1::Package pkg = PackageFromArg(pkg_arg);
            ThrowIfWrongNetwork(pkg);
            std::string error;
            int attached = 0;
            if (!sigs.isNull() && sigs.isArray()) {
                const auto& values = sigs.getValues();
                for (size_t i = 0; i < values.size(); ++i) {
                    if (!InsertExternalSig(pkg, i, values[i], error)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, error.empty() ? bcp1::ERR_CORRUPT_SIGNATURE : error);
                    }
                    ++attached;
                }
            }
            UniValue o = bcp1::Encode(pkg);
            CMutableTransaction signed_tx;
            const bool complete = bcp1::TryExtractSignedTx(pkg, signed_tx, error);
            o.pushKV("complete", complete);
            o.pushKV("broadcast", false);
            o.pushKV("signatures_attached", attached);
            o.pushKV("in_process_sign", false);
            if (complete) {
                o.pushKV("hex", EncodeHexTx(CTransaction(signed_tx)));
                o.pushKV("txid", CTransaction(signed_tx).GetHash().GetHex());
            } else if (!error.empty()) {
                o.pushKV("error", error);
            }
            return o;
        },
    };
}

RPCHelpMan getdepositstatus()
{
    return RPCHelpMan{
        "getdepositstatus",
        "Deposit state for txid/vout. 1 confirmation = included in a block connected to the active chain tip. Reorg to mempool = REORGED. Not irreversible.\n",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transaction id", RPCArgOptions{.skip_type_check = true}},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Output index"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "BCP/1 fields"},
            {RPCResult::Type::STR, "status", "MEMPOOL|CONFIRMED|REORGED|CONFLICTED|SPENT|UNKNOWN"},
            {RPCResult::Type::NUM, "confirmations", "Active-chain depth"},
            {RPCResult::Type::BOOL, "irreversible", "Always false"},
            {RPCResult::Type::ELISION, "", "block hash/height / address / amount_atoms"},
        }},
        RPCExamples{HelpExampleCli("getdepositstatus", "\"txid\" 0")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            (void)self;
            pwallet->BlockUntilSyncedToCurrentChain();
            const UniValue& first = request.params[0];
            uint256 txid;
            int64_t vout64 = -1;
            if (first.isObject()) {
                txid = ParseHashV(first["txid"], "txid");
                vout64 = first["vout"].getInt<int64_t>();
            } else {
                txid = ParseHashV(first, "txid");
                if (!request.params[1].isNull()) vout64 = request.params[1].getInt<int64_t>();
            }
            if (vout64 < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "vout cannot be negative");
            LOCK(pwallet->cs_wallet);
            UniValue result = GetDepositStatusUniValue(*pwallet, txid, static_cast<uint32_t>(vout64));
            if (!result.exists("irreversible")) result.pushKV("irreversible", false);
            return result;
        },
    };
}

RPCHelpMan listdepositutxos()
{
    return RPCHelpMan{
        "listdepositutxos",
        "List wallet deposit UTXOs with BCP/1 status fields. Includes watch-only outputs. Does not spend.\n",
        {{"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "", {
            {"minconf", RPCArg::Type::NUM, RPCArg::Default{0}, "Minimum confirmations"},
            {"min_confirmations", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Alias of minconf"},
            {"maxconf", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Maximum confirmations"},
            {"min_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Minimum value"},
            {"include_spent", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include spent outputs"},
            {"include_change", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include change"},
        }}},
        RPCResult{RPCResult::Type::ARR, "", "", {{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "BCP/1 fields"},
            {RPCResult::Type::STR, "status", ""},
            {RPCResult::Type::STR, "address", /*optional=*/true, ""},
            {RPCResult::Type::ELISION, "", "txid / vout / amount / confirmations"},
        }}}},
        RPCExamples{HelpExampleCli("listdepositutxos", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            (void)self;
            pwallet->BlockUntilSyncedToCurrentChain();
            ListDepositUtxoFilter filter;
            if (!request.params[0].isNull() && request.params[0].isObject()) {
                const UniValue& o = request.params[0];
                if (o.exists("minconf")) filter.min_confirmations = o["minconf"].getInt<int>();
                if (o.exists("min_confirmations")) filter.min_confirmations = o["min_confirmations"].getInt<int>();
                if (o.exists("maxconf")) filter.max_confirmations = o["maxconf"].getInt<int>();
                if (o.exists("max_confirmations")) filter.max_confirmations = o["max_confirmations"].getInt<int>();
                if (o.exists("min_amount")) filter.min_amount = AmountFromValue(o["min_amount"]);
                if (o.exists("min_input_value")) filter.min_amount = AmountFromValue(o["min_input_value"]);
                if (o.exists("include_spent")) filter.include_spent = o["include_spent"].get_bool();
                if (o.exists("include_change")) filter.include_change = o["include_change"].get_bool();
                if (o.exists("addresses") && o["addresses"].isArray()) {
                    for (const UniValue& a : o["addresses"].getValues()) filter.addresses.push_back(a.get_str());
                }
            }
            LOCK(pwallet->cs_wallet);
            return ListDepositUtxosUniValue(*pwallet, filter);
        },
    };
}

RPCHelpMan planconsolidation()
{
    return RPCHelpMan{"planconsolidation", "Plan a UTXO consolidation without building or broadcasting a transaction.\n",
        {{"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "", {
            {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, ""},
            {"min_confirmations", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, ""},
            {"max_inputs", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, ""},
            {"batch_size", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, ""},
            {"target_utxo_count", RPCArg::Type::NUM, RPCArg::Default{1}, ""},
            {"fee_ceiling", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, ""},
            {"minimum_input_value", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, ""},
        }}},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "BCP/1 fields"},
            {RPCResult::Type::ARR, "inputs", "Selected UTXOs", {
                {RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "BCP/1 fields"},
                    {RPCResult::Type::STR_HEX, "txid", "Previous transaction id"},
                    {RPCResult::Type::NUM, "vout", "Output index"},
                    {RPCResult::Type::ELISION, "", "amount_atoms"},
                }},
            }},
            {RPCResult::Type::ELISION, "", "fee / target_utxo_count"},
        }},
        RPCExamples{HelpExampleCli("planconsolidation", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            (void)self;
            pwallet->BlockUntilSyncedToCurrentChain();
            UniValue options = request.params[0].isNull() ? UniValue(UniValue::VOBJ) : request.params[0];
            return PlanCoins(*pwallet, options, /*create_tx=*/false);
        },
    };
}

RPCHelpMan createconsolidationtx()
{
    return RPCHelpMan{"createconsolidationtx",
        "Build an unsigned consolidation transaction to a single change/omnibus output (BTXPSBT). Does not sign with wallet keys. Does not broadcast.\n",
        {
            {"change_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "P2MR change/sweep destination, or a plan object", RPCArgOptions{.skip_type_check = true}},
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "", {
                {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, ""},
                {"max_inputs", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, ""},
                {"fee_ceiling", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, ""},
                {"plan", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "planconsolidation result", std::vector<RPCArg>{}},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "BCP/1 fields"},
            {RPCResult::Type::STR, "format", "BTXPSBT"},
            {RPCResult::Type::BOOL, "broadcast", "Always false"},
            {RPCResult::Type::ELISION, "", "unsigned_tx_hex / selected_utxos / fee"},
        }},
        RPCExamples{HelpExampleCli("createconsolidationtx", "\"btxrt1z...\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            (void)self;
            pwallet->BlockUntilSyncedToCurrentChain();
            UniValue options{UniValue::VOBJ};
            if (request.params[0].isObject()) {
                options = request.params[0];
            } else if (request.params[1].isObject()) {
                options = request.params[1];
            }
            if (request.params[0].isStr()) {
                options.pushKV("change_address", request.params[0].get_str());
            }
            return PlanCoins(*pwallet, options, /*create_tx=*/true);
        },
    };
}

RPCHelpMan estimateconsolidationfee()
{
    return RPCHelpMan{"estimateconsolidationfee", "Estimate fee/weight for a consolidation plan without broadcasting.\n",
        {{"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "", {
            {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, ""},
            {"max_inputs", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, ""},
            {"change_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "If set, build an unsigned tx to price the fee"},
            {"fee_ceiling", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, ""},
            {"plan", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "planconsolidation result", std::vector<RPCArg>{}},
        }, RPCArgOptions{.skip_type_check = true}}},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "BCP/1 fields"},
            {RPCResult::Type::NUM, "input_count", ""},
            {RPCResult::Type::ELISION, "", "fee_atoms / weight"},
        }},
        RPCExamples{HelpExampleCli("estimateconsolidationfee", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            (void)self;
            pwallet->BlockUntilSyncedToCurrentChain();
            UniValue options = request.params[0].isNull() ? UniValue(UniValue::VOBJ) : request.params[0];
            options = NormalizePlanOptions(options);
            const bool can_price = options.exists("change_address") || options.exists("inputs") || options.exists("selected_utxos");
            if (can_price) {
                try {
                    UniValue funded = PlanCoins(*pwallet, options, /*create_tx=*/true);
                    UniValue o(UniValue::VOBJ);
                    if (funded.exists("selected_utxos")) {
                        o.pushKV("input_count", static_cast<int>(funded["selected_utxos"].size()));
                    } else if (funded.exists("input_count")) {
                        o.pushKV("input_count", funded["input_count"]);
                    }
                    if (funded.exists("fee_atoms")) o.pushKV("fee_atoms", funded["fee_atoms"]);
                    if (funded.exists("fee")) o.pushKV("fee", funded["fee"]);
                    o.pushKV("would_broadcast", false);
                    return o;
                } catch (const UniValue&) {
                    // Fall through to an unsigned plan when change/omnibus cannot be priced.
                }
            }
            return PlanCoins(*pwallet, options, /*create_tx=*/false);
        },
    };
}

RPCHelpMan createexchangebatch()
{
    return RPCHelpMan{
        "createexchangebatch",
        "Build one unsigned transaction with many {address, amount} withdrawal outputs plus change, selected UTXOs, and signing digests.\n"
        "Does not sign with wallet keys. Does not broadcast. Follow with prepareexternalsign / getsigningdigests / finalizeexternalsign / testmempoolaccept / sendrawtransaction.\n",
        {
            {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Withdrawal outputs", {
                {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "", {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "P2MR destination"},
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Amount in BTX"},
                    {"amount_atoms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Amount in atoms"},
                }},
            }, RPCArgOptions{.skip_type_check = true}},
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "", {
                {"change_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Change destination"},
                {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, ""},
                {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Fee rate in " + CURRENCY_ATOM + "/vB"},
                {"fee_ceiling", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, ""},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "BCP/1 fields"},
            {RPCResult::Type::STR, "format", "BTXPSBT"},
            {RPCResult::Type::ARR, "selected_utxos", "Chosen inputs", {
                {RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "BCP/1 fields"},
                    {RPCResult::Type::STR_HEX, "txid", "Previous transaction id"},
                    {RPCResult::Type::NUM, "vout", "Output index"},
                    {RPCResult::Type::ELISION, "", "amount_atoms"},
                }},
            }},
            {RPCResult::Type::ARR, "digests", "Signing digests", {
                {RPCResult::Type::STR_HEX, "digest", "Canonical P2MR digest"},
                {RPCResult::Type::ELISION, "", "index / path / pubkey"},
            }},
            {RPCResult::Type::BOOL, "broadcast", "Always false"},
            {RPCResult::Type::ELISION, "", "unsigned_tx_hex / outputs / fee"},
        }},
        RPCExamples{HelpExampleCli("createexchangebatch", "'[{\"address\":\"btxrt1z...\",\"amount\":0.1}]'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            (void)self;
            pwallet->BlockUntilSyncedToCurrentChain();
            std::vector<CRecipient> recs = RecipientsFromValue(request.params[0]);
            UniValue options = request.params[1].isNull() ? UniValue(UniValue::VOBJ) : request.params[1];
            if (request.params[0].isObject()) {
                if (request.params[0].exists("change_address") && !options.exists("change_address")) {
                    options.pushKV("change_address", request.params[0]["change_address"]);
                }
            }
            CCoinControl cc = CoinControlFromOptions(*pwallet, options, /*default_minconf=*/1);
            UniValue funded = FundedPackage(*pwallet, recs, cc, std::nullopt);
            if (options.exists("fee_ceiling") && funded.exists("fee_atoms") &&
                funded["fee_atoms"].getInt<int64_t>() > AmountFromValue(options["fee_ceiling"])) {
                throw JSONRPCError(RPC_WALLET_ERROR, "estimated fee exceeds fee_ceiling");
            }
            return funded;
        },
    };
}

Span<const CRPCCommand> GetBCP1WalletRPCCommands()
{
    static const CRPCCommand commands[]{
        {"wallet", &getexchangereadiness},
        {"wallet", &deriveexchangeaddress},
        {"wallet", &importdepositpool},
        {"wallet", &prepareexternalsign},
        {"wallet", &getsigningdigests},
        {"wallet", &finalizeexternalsign},
        {"wallet", &getdepositstatus},
        {"wallet", &listdepositutxos},
        {"wallet", &planconsolidation},
        {"wallet", &createconsolidationtx},
        {"wallet", &estimateconsolidationfee},
        {"wallet", &createexchangebatch},
    };
    return commands;
}

} // namespace wallet
