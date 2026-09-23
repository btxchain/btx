// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/bounty_funding.h>

#include <addresstype.h>
#include <coins.h>
#include <consensus/amount.h>
#include <core_io.h>
#include <key_io.h>
#include <modelnet/bounty.h>
#include <modelnet/types.h>
#include <pqkey.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <script/pqm.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <span.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/coincontrol.h>
#include <wallet/rpc/util.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace wallet {
namespace {

bool NormalizeKey(const std::string& in, std::string& out, std::string& err)
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
    if (IsHex(s)) {
        s = ToLower(s);
        const auto key = ParseHex(s);
        if (key.size() == MLDSA44_PUBKEY_SIZE) {
            out = HexStr(key);
            return true;
        }
        err = "council/refund key must be ML-DSA-44 hex";
        return false;
    }
    err = "PQ key";
    return false;
}

bool ExpandDescriptor(const std::string& descriptor, CScript& script, std::string& canonical, std::string& err)
{
    FlatSigningProvider provider;
    std::string parse_err;
    auto parsed = Parse(descriptor, provider, parse_err, /*require_checksum=*/false);
    if (parsed.empty() || !parsed[0]) {
        err = parse_err.empty() ? "descriptor parse failed" : parse_err;
        return false;
    }
    canonical = parsed[0]->ToString();
    std::vector<CScript> scripts;
    FlatSigningProvider out;
    if (!parsed[0]->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, scripts, out) || scripts.size() != 1) {
        err = "descriptor expand failed";
        return false;
    }
    script = scripts[0];
    return true;
}

} // namespace

bool ExactTwoLeafTree(const std::string& descriptor, std::string& err)
{
    const int commas_refund = static_cast<int>(std::count(descriptor.begin(), descriptor.end(), ','));
    (void)commas_refund;
    const bool cltv = descriptor.find("cltv_multi_pq(") != std::string::npos ||
                       descriptor.find("cltv_sortedmulti_pq(") != std::string::npos;
    const bool htlc = descriptor.find("htlc_sha256(") != std::string::npos;
    const bool refund = descriptor.find("refund(") != std::string::npos;
    if (descriptor.find("ctv(") != std::string::npos) {
        err = "unsupported extra leaf";
        return false;
    }
    if (!(cltv || htlc) || !refund) {
        err = "exact two-leaf tree required";
        return false;
    }
    if (cltv && htlc) {
        err = "exact two leaves";
        return false;
    }
    const auto first = descriptor.find("mr(");
    if (first == std::string::npos) {
        err = "mr() required";
        return false;
    }
    if (descriptor.find("mr(", first + 3) != std::string::npos) {
        err = "nested mr forbidden";
        return false;
    }
    return true;
}

bool BuildBountyEscrowDescriptor(BountyEscrowPlan& plan, std::string& err)
{
    if (plan.award_height < 1 || plan.award_height >= 500000000 || plan.refund_height < 1 ||
        plan.refund_height >= 500000000) {
        err = "height range; timestamps >=500000000 rejected";
        return false;
    }
    if (plan.council_keys.size() < 2 || plan.council_keys.size() > 8) {
        err = "council size/threshold";
        return false;
    }
    if (plan.threshold < 1 || plan.threshold > static_cast<int>(plan.council_keys.size())) {
        err = "council size/threshold";
        return false;
    }
    std::set<std::string> uniq;
    std::vector<std::string> keys;
    for (const auto& k : plan.council_keys) {
        std::string n;
        if (!NormalizeKey(k, n, err)) return false;
        if (!uniq.insert(n).second) {
            err = "duplicate council key";
            return false;
        }
        keys.push_back(n);
    }
    std::string refund;
    if (!NormalizeKey(plan.refund_key, refund, err)) return false;
    plan.refund_key = refund;
    if (plan.principal_atoms <= 0 || plan.principal_atoms > modelnet::MAX_MONEY_ATOMS) {
        err = "MoneyRange";
        return false;
    }
    std::string body = strprintf("mr(cltv_multi_pq(%u,%u", plan.award_height, plan.threshold);
    for (const auto& k : keys) body += "," + k;
    body += strprintf("),refund(%u,%s))", plan.refund_height, refund);
    const std::string with = AddChecksum(body);
    std::string canonical;
    if (!ExpandDescriptor(with, plan.output_script, canonical, err)) return false;
    if (!ExactTwoLeafTree(canonical, err)) return false;
    plan.descriptor = canonical;
    return true;
}

bool BuildStagedHtlcDescriptor(BountyEscrowPlan& plan, std::string& err)
{
    if (plan.refund_height < 1 || plan.refund_height >= 500000000) {
        err = "height range";
        return false;
    }
    std::string refund, claimant;
    if (!NormalizeKey(plan.refund_key, refund, err)) return false;
    if (!NormalizeKey(plan.claimant_key, claimant, err)) return false;
    plan.refund_key = refund;
    plan.claimant_key = claimant;
    if (plan.hashlock_hex.size() != 64) {
        err = "sha256 hashlock";
        return false;
    }
    const std::string body = strprintf("mr(htlc_sha256(%s,%s),refund(%u,%s))", ToLower(plan.hashlock_hex), claimant,
                                       plan.refund_height, refund);
    const std::string with = AddChecksum(body);
    std::string canonical;
    if (!ExpandDescriptor(with, plan.output_script, canonical, err)) return false;
    if (!ExactTwoLeafTree(canonical, err)) return false;
    plan.descriptor = canonical;
    return true;
}

bool PrepareBountyFunding(CWallet& wallet, BountyEscrowPlan& plan, std::string& err)
{
    if (plan.output_script.empty() && !BuildBountyEscrowDescriptor(plan, err)) return false;
    if (plan.fee_reserve_atoms > 0 && plan.fee_atoms > plan.fee_reserve_atoms) {
        err = "reserve exceeded";
        return false;
    }
    CTxDestination dest;
    if (!ExtractDestination(plan.output_script, dest)) dest = CNoDestination(plan.output_script);
    const std::vector<CRecipient> recipients{{dest, plan.principal_atoms, /*fSubtractFeeFromAmount=*/false}};
    CCoinControl coin_control;
    wallet.BlockUntilSyncedToCurrentChain();
    LOCK(wallet.cs_wallet);
    auto res = CreateTransaction(wallet, recipients, /*change_pos=*/std::nullopt, coin_control, /*sign=*/false);
    if (!res) {
        err = util::ErrorString(res).original;
        return false;
    }
    if (plan.fee_reserve_atoms > 0 && res->fee > plan.fee_reserve_atoms) {
        err = "reserve exceeded";
        return false;
    }
    plan.fee_atoms = res->fee;
    plan.unsigned_hex = EncodeHexTx(*res->tx);
    plan.unsigned_txid = res->tx->GetHash().ToUint256();
    if (plan.plan_id.empty()) plan.plan_id = plan.unsigned_txid.GetHex();
    return true;
}

bool InspectBountyTransaction(const BountyEscrowPlan& plan_in, const CMutableTransaction& tx, UniValue& out, std::string& err)
{
    BountyEscrowPlan plan = plan_in;
    if (plan.output_script.empty()) {
        if (!plan.hashlock_hex.empty() && !plan.claimant_key.empty()) {
            if (!BuildStagedHtlcDescriptor(plan, err)) return false;
        } else if (!plan.council_keys.empty() && !plan.refund_key.empty()) {
            if (!BuildBountyEscrowDescriptor(plan, err)) return false;
        }
    }
    out.setObject();
    out.pushKV("inputs", static_cast<int>(tx.vin.size()));
    out.pushKV("outputs", static_cast<int>(tx.vout.size()));
    bool found = false;
    bool extra = false;
    for (const auto& vout : tx.vout) {
        if (!plan.output_script.empty() && vout.scriptPubKey == plan.output_script) {
            if (plan.principal_atoms > 0 && vout.nValue != plan.principal_atoms) {
                err = "principal changed";
                return false;
            }
            found = true;
        } else if (!plan.output_script.empty()) {
            extra = true;
        }
    }
    if (!plan.output_script.empty() && !found) {
        err = "escrow output missing or keys/heights mutated";
        return false;
    }
    out.pushKV("escrow_output_present", found);
    out.pushKV("unauthorized_extra_output", extra && found && tx.vout.size() > 2);
    if (!plan.unsigned_txid.IsNull()) {
        CMutableTransaction skel = tx;
        for (auto& in : skel.vin) {
            in.scriptSig.clear();
            in.scriptWitness.SetNull();
        }
        const uint256 skel_id = skel.GetHash().ToUint256();
        if (skel_id != plan.unsigned_txid && tx.GetHash().ToUint256() != plan.unsigned_txid) {
            err = "transaction fingerprint mutated";
            return false;
        }
    }
    out.pushKV("descriptor", plan.descriptor);
    out.pushKV("sighash", "ALL");
    return true;
}

bool SignBountyTransaction(CWallet& wallet, BountyEscrowPlan& plan, CMutableTransaction& tx, std::string& err)
{
    UniValue insp;
    if (!InspectBountyTransaction(plan, tx, insp, err)) return false;
    EnsureWalletIsUnlocked(wallet);
    LOCK(wallet.cs_wallet);
    std::map<COutPoint, Coin> coins;
    for (const CTxIn& txin : tx.vin) coins[txin.prevout];
    wallet.chain().findCoins(coins);
    std::map<int, bilingual_str> input_errors;
    const bool complete = wallet.SignTransaction(tx, coins, SIGHASH_ALL, input_errors);
    if (!complete && !input_errors.empty()) {
        err = input_errors.begin()->second.original;
        return false;
    }
    return true;
}

UniValue BountyPlanToJson(const BountyEscrowPlan& plan)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("plan_id", plan.plan_id);
    o.pushKV("bounty_id", plan.bounty_id);
    o.pushKV("round_id", plan.round_id);
    o.pushKV("lot_id", plan.lot_id);
    o.pushKV("principal_atoms", std::to_string(plan.principal_atoms));
    o.pushKV("fee_reserve_atoms", std::to_string(plan.fee_reserve_atoms));
    o.pushKV("fee_atoms", plan.fee_atoms);
    o.pushKV("award_height", static_cast<int64_t>(plan.award_height));
    o.pushKV("refund_height", static_cast<int64_t>(plan.refund_height));
    o.pushKV("threshold", plan.threshold);
    o.pushKV("refund_key", plan.refund_key);
    o.pushKV("descriptor", plan.descriptor);
    if (!plan.output_script.empty()) o.pushKV("output_script", HexStr(plan.output_script));
    if (!plan.unsigned_hex.empty()) o.pushKV("unsigned_hex", plan.unsigned_hex);
    if (!plan.unsigned_txid.IsNull()) o.pushKV("unsigned_txid", plan.unsigned_txid.GetHex());
    if (!plan.destination.empty()) o.pushKV("destination", plan.destination);
    if (!plan.prev_txid.IsNull()) o.pushKV("prev_txid", plan.prev_txid.GetHex());
    if (plan.prev_vout >= 0) o.pushKV("prev_vout", plan.prev_vout);
    if (!plan.signed_hex.empty()) {
        o.pushKV("signed_hex", plan.signed_hex);
        o.pushKV("hex", plan.signed_hex);
    }
    o.pushKV("complete", plan.complete);
    if (!plan.selected_path.empty()) o.pushKV("selected_path", plan.selected_path);
    o.pushKV("automatic_spend", 0);
    o.pushKV("helper_defaults", false);
    return o;
}

bool ParseBountyPlan(const UniValue& o, BountyEscrowPlan& plan, std::string& err)
{
    plan = {};
    if (!o.isObject()) {
        err = "plan object";
        return false;
    }
    auto S = [&](const char* k, std::string& d) {
        if (o.exists(k) && o[k].isStr()) d = o[k].get_str();
    };
    S("bounty_id", plan.bounty_id);
    S("round_id", plan.round_id);
    S("lot_id", plan.lot_id);
    S("plan_id", plan.plan_id);
    S("refund_key", plan.refund_key);
    S("descriptor", plan.descriptor);
    S("unsigned_hex", plan.unsigned_hex);
    S("claimant_key", plan.claimant_key);
    S("hashlock_hex", plan.hashlock_hex);
    S("destination", plan.destination);
    S("signed_hex", plan.signed_hex);
    S("selected_path", plan.selected_path);
    if (o.exists("principal_atoms")) {
        if (o["principal_atoms"].isStr()) {
            if (!modelnet::CanonicalAtoms(o["principal_atoms"].get_str(), plan.principal_atoms, err)) return false;
        } else {
            plan.principal_atoms = o["principal_atoms"].getInt<int64_t>();
        }
    }
    if (o.exists("fee_reserve_atoms")) {
        plan.fee_reserve_atoms = o["fee_reserve_atoms"].isStr() ? std::stoll(o["fee_reserve_atoms"].get_str()) :
                                                                  o["fee_reserve_atoms"].getInt<int64_t>();
    }
    if (o.exists("fee_atoms")) {
        plan.fee_atoms = o["fee_atoms"].isStr() ? std::stoll(o["fee_atoms"].get_str()) :
                                                 o["fee_atoms"].getInt<int64_t>();
    }
    if (o.exists("award_height")) plan.award_height = static_cast<uint32_t>(o["award_height"].getInt<int64_t>());
    if (o.exists("refund_height")) plan.refund_height = static_cast<uint32_t>(o["refund_height"].getInt<int64_t>());
    if (o.exists("threshold")) plan.threshold = o["threshold"].getInt<int>();
    if (o.exists("council_keys") && o["council_keys"].isArray()) {
        for (const auto& k : o["council_keys"].getValues()) plan.council_keys.push_back(k.get_str());
    }
    if (o.exists("output_script") && o["output_script"].isStr()) {
        const auto raw = ParseHex(o["output_script"].get_str());
        plan.output_script = CScript(raw.begin(), raw.end());
    }
    if (o.exists("unsigned_txid") && o["unsigned_txid"].isStr()) {
        const auto parsed = uint256::FromHex(o["unsigned_txid"].get_str());
        if (parsed) plan.unsigned_txid = *parsed;
    }
    if (o.exists("refund_pubkey") && plan.refund_key.empty()) plan.refund_key = o["refund_pubkey"].get_str();
    auto parse_txid = [&](const std::string& hex) -> bool {
        const auto parsed = uint256::FromHex(hex);
        if (!parsed) {
            err = "prev_txid";
            return false;
        }
        plan.prev_txid = *parsed;
        return true;
    };
    if (o.exists("prevout") && o["prevout"].isObject()) {
        const UniValue& p = o["prevout"];
        if (p.exists("txid") && p["txid"].isStr() && !parse_txid(p["txid"].get_str())) return false;
        if (p.exists("vout")) plan.prev_vout = p["vout"].getInt<int>();
    }
    if (o.exists("txid") && o["txid"].isStr() && plan.prev_txid.IsNull() && !parse_txid(o["txid"].get_str())) {
        return false;
    }
    if (o.exists("vout") && plan.prev_vout < 0) plan.prev_vout = o["vout"].getInt<int>();
    if (o.exists("prev_txid") && o["prev_txid"].isStr() && !parse_txid(o["prev_txid"].get_str())) return false;
    if (o.exists("prev_vout")) plan.prev_vout = o["prev_vout"].getInt<int>();
    if (o.exists("outpoint") && o["outpoint"].isStr()) {
        const std::string s = o["outpoint"].get_str();
        const auto colon = s.rfind(':');
        if (colon == std::string::npos || colon == 0 || colon + 1 >= s.size()) {
            err = "outpoint";
            return false;
        }
        if (!parse_txid(s.substr(0, colon))) return false;
        plan.prev_vout = std::stoi(s.substr(colon + 1));
    }
    return true;
}

namespace {

bool IsBountyRefundLeaf(const std::vector<unsigned char>& script, std::vector<unsigned char>& pubkey_out)
{
    if (script.size() < 4) return false;
    size_t i = 0;
    if (script[0] == OP_0 || (script[0] >= OP_1 && script[0] <= OP_16)) {
        i = 1;
    } else if (script[0] >= 0x01 && script[0] <= 0x4b) {
        i = 1 + script[0];
    } else {
        return false;
    }
    if (i + 2 > script.size()) return false;
    if (script[i] != OP_CHECKLOCKTIMEVERIFY || script[i + 1] != OP_DROP) return false;
    PQAlgorithm algo{PQAlgorithm::ML_DSA_44};
    Span<const unsigned char> pubkey;
    size_t push_consumed{0};
    const size_t key_offset = i + 2;
    if (!ParseP2MRAnyPubkeyPush(script, key_offset, algo, pubkey, push_consumed)) return false;
    const size_t tail = key_offset + push_consumed;
    if (script.size() != tail + 1 || script[tail] != GetP2MRChecksigOpcode(algo)) return false;
    pubkey_out.assign(pubkey.begin(), pubkey.end());
    return true;
}

bool KeyBytesFromNormalized(const std::string& n, std::vector<unsigned char>& out, std::string& err)
{
    if (n.rfind("pk_slh(", 0) == 0) {
        const auto close = n.find(')');
        if (close == std::string::npos) {
            err = "PQ key";
            return false;
        }
        out = ParseHex(n.substr(7, close - 7));
        return !out.empty();
    }
    if (!IsHex(n)) {
        err = "PQ key";
        return false;
    }
    out = ParseHex(n);
    return !out.empty();
}

int CollectWalletPQKeys(CWallet& wallet, const std::vector<std::vector<unsigned char>>& pubkeys, FlatSigningProvider& provider)
{
    int found = 0;
    for (const auto& pk : pubkeys) {
        for (ScriptPubKeyMan* spk_man : wallet.GetAllScriptPubKeyMans()) {
            auto* desc_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
            if (desc_man == nullptr) continue;
            std::unique_ptr<FlatSigningProvider> keys = desc_man->GetSigningProvider(Span<const unsigned char>{pk});
            if (keys && keys->GetPQKey(pk) != nullptr) {
                provider.Merge(std::move(*keys));
                ++found;
                break;
            }
        }
    }
    return found;
}

} // namespace

bool InspectBountySpend(const BountyEscrowPlan& plan_in, const CMutableTransaction& tx, UniValue& out, std::string& err)
{
    BountyEscrowPlan plan = plan_in;
    if (plan.output_script.empty() && !plan.council_keys.empty() && !plan.refund_key.empty()) {
        if (!BuildBountyEscrowDescriptor(plan, err)) return false;
    }
    out.setObject();
    out.pushKV("inputs", static_cast<int>(tx.vin.size()));
    out.pushKV("outputs", static_cast<int>(tx.vout.size()));
    if (tx.vin.size() != 1 || tx.vout.size() != 1) {
        err = "exactly one input and one output";
        return false;
    }
    if (tx.vin[0].nSequence == CTxIn::SEQUENCE_FINAL) {
        err = "sequence must be non-final for CLTV";
        return false;
    }
    if (plan.prev_vout >= 0) {
        if (tx.vin[0].prevout.n != static_cast<uint32_t>(plan.prev_vout) ||
            tx.vin[0].prevout.hash != Txid::FromUint256(plan.prev_txid)) {
            err = "wrong prevout";
            return false;
        }
    }
    const uint32_t locktime = tx.nLockTime;
    std::string path = plan.selected_path;
    if (path.empty()) {
        if (plan.award_height > 0 && locktime == plan.award_height) path = "award";
        else if (plan.refund_height > 0 && locktime == plan.refund_height) path = "refund";
    }
    if (path == "award" && plan.award_height > 0 && locktime != plan.award_height) {
        err = "locktime does not match award_height";
        return false;
    }
    if (path == "refund" && plan.refund_height > 0 && locktime != plan.refund_height) {
        err = "locktime does not match refund_height";
        return false;
    }
    if (path.empty() && (plan.award_height > 0 || plan.refund_height > 0) &&
        locktime != plan.award_height && locktime != plan.refund_height) {
        err = "locktime does not match award_height or refund_height";
        return false;
    }
    if (!plan.destination.empty()) {
        const CTxDestination dest = DecodeDestination(plan.destination);
        if (!IsValidDestination(dest) || tx.vout[0].scriptPubKey != GetScriptForDestination(dest)) {
            err = "destination mutated";
            return false;
        }
    }
    if (plan.principal_atoms > 0 && plan.fee_atoms > 0 &&
        tx.vout[0].nValue != plan.principal_atoms - plan.fee_atoms) {
        err = "principal changed";
        return false;
    }
    out.pushKV("escrow_output_present", false);
    out.pushKV("unauthorized_extra_output", false);
    out.pushKV("locktime", static_cast<int64_t>(locktime));
    out.pushKV("selected_path", path);
    out.pushKV("descriptor", plan.descriptor);
    out.pushKV("sighash", "ALL");
    out.pushKV("timelock_enforced", true);
    return true;
}

bool PrepareBountyLeafSpend(CWallet& wallet, BountyEscrowPlan& plan, BountySpendPath path, std::string& err)
{
    if (plan.output_script.empty() || plan.descriptor.empty()) {
        if (!BuildBountyEscrowDescriptor(plan, err)) return false;
    }
    if (plan.destination.empty()) {
        err = "destination required";
        return false;
    }
    if (plan.prev_vout < 0 || plan.prev_txid.IsNull()) {
        err = "funding outpoint required";
        return false;
    }
    const CTxDestination dest = DecodeDestination(plan.destination);
    if (!IsValidDestination(dest)) {
        err = "destination";
        return false;
    }
    const uint32_t locktime = path == BountySpendPath::AWARD ? plan.award_height : plan.refund_height;
    if (locktime < 1 || locktime >= 500000000) {
        err = "height range; timestamps >=500000000 rejected";
        return false;
    }
    int64_t fee = plan.fee_atoms;
    if (fee <= 0) fee = 1'000'000;
    if (plan.fee_reserve_atoms > 0 && fee > plan.fee_reserve_atoms) {
        err = "reserve exceeded";
        return false;
    }
    plan.fee_atoms = fee;
    plan.selected_path = path == BountySpendPath::AWARD ? "award" : "refund";

    FlatSigningProvider parse_provider;
    std::string parse_err;
    auto parsed = Parse(plan.descriptor, parse_provider, parse_err, /*require_checksum=*/false);
    if (parsed.empty() || !parsed[0]) {
        err = parse_err.empty() ? "descriptor parse failed" : parse_err;
        return false;
    }
    std::vector<CScript> scripts;
    FlatSigningProvider expand_out;
    if (!parsed[0]->Expand(/*pos=*/0, DUMMY_SIGNING_PROVIDER, scripts, expand_out) || scripts.size() != 1) {
        err = "descriptor expand failed";
        return false;
    }
    if (plan.output_script.empty()) plan.output_script = scripts[0];
    if (scripts[0] != plan.output_script) {
        err = "descriptor does not match output_script";
        return false;
    }
    int witver{-1};
    std::vector<unsigned char> program;
    if (!scripts[0].IsWitnessProgram(witver, program) || witver != 2 || program.size() != uint256::size()) {
        err = "descriptor did not expand to a P2MR output";
        return false;
    }
    const uint256 merkle{Span<const unsigned char>(program)};
    P2MRSpendData spenddata;
    if (!expand_out.GetP2MRSpendData(WitnessV2P2MR{merkle}, spenddata) || spenddata.scripts.empty()) {
        err = "descriptor produced no P2MR spend data";
        return false;
    }
    std::vector<unsigned char> refund_leaf, refund_ctrl, refund_pk;
    std::vector<unsigned char> award_leaf, award_ctrl;
    for (const auto& [leaf_script, controls] : spenddata.scripts) {
        if (controls.empty()) {
            err = "missing control block";
            return false;
        }
        std::vector<unsigned char> pk;
        if (IsBountyRefundLeaf(leaf_script, pk)) {
            if (!refund_leaf.empty()) {
                err = "more than one refund leaf";
                return false;
            }
            refund_leaf = leaf_script;
            refund_ctrl = *controls.begin();
            refund_pk = std::move(pk);
        } else {
            if (!award_leaf.empty()) {
                err = "more than one award leaf";
                return false;
            }
            award_leaf = leaf_script;
            award_ctrl = *controls.begin();
        }
    }
    if (refund_leaf.empty() || award_leaf.empty()) {
        err = "exact two-leaf tree required";
        return false;
    }

    wallet.BlockUntilSyncedToCurrentChain();
    const int tip = wallet.chain().getHeight().value_or(-1);
    if (tip < static_cast<int>(locktime)) {
        err = strprintf("timelock not mature (tip %d < locktime %u)", tip, locktime);
        return false;
    }

    const COutPoint outpoint{Txid::FromUint256(plan.prev_txid), static_cast<uint32_t>(plan.prev_vout)};
    std::map<COutPoint, Coin> coins;
    coins[outpoint];
    wallet.chain().findCoins(coins);
    const auto it = coins.find(outpoint);
    if (it == coins.end() || it->second.IsSpent()) {
        err = "outpoint not found in the UTXO set (unconfirmed, spent, or unknown)";
        return false;
    }
    const CTxOut prev_txout = it->second.out;
    if (prev_txout.scriptPubKey != plan.output_script) {
        err = "outpoint scriptPubKey does not match the descriptor";
        return false;
    }
    if (plan.principal_atoms > 0 && prev_txout.nValue != plan.principal_atoms) {
        err = "principal changed";
        return false;
    }
    if (plan.principal_atoms <= 0) plan.principal_atoms = prev_txout.nValue;
    const CAmount out_value = prev_txout.nValue - fee;
    if (out_value <= 0) {
        err = "fee exceeds the funding amount";
        return false;
    }

    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION;
    mtx.nLockTime = locktime;
    constexpr uint32_t max_sequence_nonfinal{CTxIn::SEQUENCE_FINAL - 1};
    mtx.vin.emplace_back(outpoint, CScript(), max_sequence_nonfinal);
    mtx.vout.emplace_back(out_value, GetScriptForDestination(dest));

    PartiallySignedTransaction psbt(mtx);
    PSBTInput& input = psbt.inputs[0];
    input.witness_utxo = prev_txout;
    input.m_p2mr_merkle_root = merkle;
    if (path == BountySpendPath::REFUND) {
        input.m_p2mr_leaf_script = refund_leaf;
        input.m_p2mr_control_block = refund_ctrl;
    } else {
        input.m_p2mr_leaf_script = award_leaf;
        input.m_p2mr_control_block = award_ctrl;
    }

    std::vector<std::vector<unsigned char>> want;
    int need = 1;
    if (path == BountySpendPath::REFUND) {
        want.push_back(refund_pk);
        need = 1;
    } else {
        need = plan.threshold > 0 ? plan.threshold : 2;
        if (!plan.council_keys.empty()) {
            for (const auto& k : plan.council_keys) {
                std::string n;
                if (!NormalizeKey(k, n, err)) return false;
                std::vector<unsigned char> bytes;
                if (!KeyBytesFromNormalized(n, bytes, err)) return false;
                want.push_back(std::move(bytes));
            }
        } else {
            size_t i = 0;
            while (i < award_leaf.size()) {
                PQAlgorithm algo{PQAlgorithm::ML_DSA_44};
                Span<const unsigned char> pk;
                size_t consumed{0};
                if (ParseP2MRAnyPubkeyPush(award_leaf, i, algo, pk, consumed)) {
                    want.emplace_back(pk.begin(), pk.end());
                    i += consumed;
                    continue;
                }
                ++i;
            }
        }
    }

    EnsureWalletIsUnlocked(wallet);
    FlatSigningProvider provider;
    int found = 0;
    {
        LOCK(wallet.cs_wallet);
        found = CollectWalletPQKeys(wallet, want, provider);
    }
    if (found < need) {
        err = strprintf("wallet holds %d of %d required %s keys", found, need,
                        path == BountySpendPath::AWARD ? "council" : "refund");
        return false;
    }

    const bool slhdsa_fips205 = wallet.SlhdsaFips205ForNextBlock();
    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbt);
    const bool complete = SignPSBTInput(provider, psbt, /*index=*/0, &txdata, SIGHASH_ALL,
                                        /*out_sigdata=*/nullptr, /*finalize=*/true, slhdsa_fips205);
    plan.complete = complete;
    if (!complete) {
        err = "failed to sign/finalize bounty leaf spend; check locktime, destination, and that this wallet holds the required keys";
        return false;
    }
    CMutableTransaction signed_mtx;
    if (!FinalizeAndExtractPSBT(psbt, signed_mtx, slhdsa_fips205)) {
        err = "failed to extract finalized bounty spend";
        return false;
    }
    UniValue insp;
    if (!InspectBountySpend(plan, signed_mtx, insp, err)) return false;
    plan.signed_hex = EncodeHexTx(CTransaction(signed_mtx));
    plan.unsigned_hex = plan.signed_hex;
    plan.unsigned_txid = signed_mtx.GetHash().ToUint256();
    if (plan.plan_id.empty()) plan.plan_id = plan.unsigned_txid.GetHex();
    return true;
}

} // namespace wallet
