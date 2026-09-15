// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/bounty_funding.h>

#include <addresstype.h>
#include <core_io.h>
#include <key_io.h>
#include <modelnet/bounty.h>
#include <modelnet/types.h>
#include <pqkey.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <script/pqm.h>
#include <script/signingprovider.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/coincontrol.h>
#include <wallet/rpc/util.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <set>

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
    if (plan.council_keys.size() < 1 || plan.council_keys.size() > 8) {
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
    return true;
}

} // namespace wallet
