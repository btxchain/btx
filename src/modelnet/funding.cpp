// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/funding.h>

#include <consensus/amount.h>
#include <core_io.h>
#include <crypto/sha256.h>
#include <key_io.h>
#include <modelnet/crypto.h>
#include <modelnet/release.h>
#include <modelnet/transfer.h>
#include <primitives/transaction.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <addresstype.h>
#include <algorithm>
#include <initializer_list>
#include <limits>
#include <optional>

namespace modelnet {
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
           s.find("htlc_tx(") != std::string::npos;
}

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
            err = "HASH160 htlc_tx / secrets are not accepted; reuse 0.34.6 htlc_sha256";
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

const UniValue& OptionsFromParams(const UniValue& params)
{
    static const UniValue empty{UniValue::VOBJ};
    if (params.isObject()) return params;
    if (!params.isArray()) return empty;
    if (params.size() > 0 && params[0].isObject()) return params[0];
    if (params.size() > 1 && params[1].isObject()) return params[1];
    if (params.size() > 2 && params[2].isObject()) return params[2];
    return empty;
}

std::string FirstStringArg(const UniValue& params)
{
    if (params.isArray() && params.size() > 0 && params[0].isStr()) return params[0].get_str();
    return {};
}

std::string HexArg(const UniValue& options, const UniValue& params, std::initializer_list<const char*> names)
{
    if (const UniValue* v = FindField(options, names)) {
        if (v->isStr()) return v->get_str();
    }
    if (params.isArray() && params.size() > 0 && params[0].isStr()) {
        for (const char* n : names) {
            if (std::string(n) == "hex" || std::string(n) == "unsigned_hex") return params[0].get_str();
        }
    }
    return {};
}

bool ExpandHtlcDescriptor(const std::string& descriptor, CScript& script_pubkey, std::string& canonical, std::string& err)
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

bool ParseInputs(const UniValue& inputs, CMutableTransaction& mtx, int64_t& in_sum, std::string& err)
{
    in_sum = 0;
    if (!inputs.isArray() || inputs.empty()) {
        err = "inputs array required to assemble an unsigned funding transaction";
        return false;
    }
    for (const auto& in : inputs.getValues()) {
        if (!in.isObject() || !in.exists("txid") || !in.exists("vout")) {
            err = "each input needs txid and vout";
            return false;
        }
        const auto txid = Txid::FromHex(in["txid"].get_str());
        if (!txid) {
            err = "txid must be 32-byte hex";
            return false;
        }
        if (!in["vout"].isNum() || in["vout"].getInt<int64_t>() < 0) {
            err = "vout out of range";
            return false;
        }
        const uint32_t vout = in["vout"].getInt<uint32_t>();
        uint32_t sequence = CTxIn::SEQUENCE_FINAL;
        if (in.exists("sequence") && in["sequence"].isNum()) {
            sequence = in["sequence"].getInt<uint32_t>();
        }
        mtx.vin.emplace_back(COutPoint(*txid, vout), CScript(), sequence);
        if (in.exists("amount_atoms") && in["amount_atoms"].isNum()) {
            const int64_t a = in["amount_atoms"].getInt<int64_t>();
            if (a < 0 || !MoneyRange(a)) {
                err = "input amount_atoms out of range";
                return false;
            }
            if (in_sum > std::numeric_limits<int64_t>::max() - a) {
                err = "input amount overflow";
                return false;
            }
            in_sum += a;
        }
    }
    return true;
}

bool MatchFrozen(const UniValue& options, const CMutableTransaction& tx, std::string& err)
{
    CMutableTransaction skeleton = tx;
    for (auto& in : skeleton.vin) {
        in.scriptSig.clear();
        in.scriptWitness.SetNull();
    }
    const uint256 txid = tx.GetHash().ToUint256();
    const uint256 skeleton_txid = skeleton.GetHash().ToUint256();
    if (const UniValue* v = FindField(options, {"unsigned_txid"})) {
        const auto want = uint256::FromHex(v->get_str());
        if (!want) {
            err = "unsigned_txid must be 32-byte hex";
            return false;
        }
        if (txid != *want && skeleton_txid != *want) {
            err = "funding template txid mutated; run preparemodelfunding again";
            return false;
        }
    }
    CScript frozen_script;
    if (const UniValue* v = FindField(options, {"output_script"})) {
        if (!v->isStr() || !IsHex(v->get_str())) {
            err = "output_script must be hex";
            return false;
        }
        const auto raw = ParseHex(v->get_str());
        frozen_script = CScript(raw.begin(), raw.end());
    }
    int64_t amount = 0;
    if (const UniValue* v = FindField(options, {"amount_atoms", "max_atoms"})) {
        if (v->isNum()) amount = v->getInt<int64_t>();
    }
    if (!frozen_script.empty()) {
        bool found = false;
        for (const auto& out : tx.vout) {
            if (out.scriptPubKey == frozen_script) {
                if (amount > 0 && out.nValue != amount) {
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

bool InputsFullySigned(const CMutableTransaction& tx)
{
    if (tx.vin.empty()) return false;
    for (const auto& in : tx.vin) {
        if (in.scriptSig.empty() && in.scriptWitness.IsNull()) return false;
    }
    return true;
}

fs::path HelperRoot(const ModelCatalog& cat)
{
    return cat.Store().Root().parent_path();
}

void MergeCampaign(const std::vector<ReleaseCampaign>& campaigns, const std::string& release_id,
                   FrozenModelFunding& f)
{
    if (release_id.empty()) return;
    Digest48 id;
    std::string err;
    if (!Digest48::FromHex(release_id, id, err)) return;
    for (const auto& c : campaigns) {
        if (!(c.release_id == id)) continue;
        if (f.key_hash_hex.empty()) f.key_hash_hex = c.key_hash.Hex();
        if (f.refund_height == 0) f.refund_height = c.refund_height;
        if (f.amount_atoms == 0 && c.target_atoms > 0) f.amount_atoms = c.target_atoms;
        if (f.max_atoms == 0 && c.target_atoms > 0) f.max_atoms = c.target_atoms;
        return;
    }
}

bool DestinationScript(const UniValue& options, CScript& script, std::string& err)
{
    if (const UniValue* v = FindField(options, {"destination_script", "scriptPubKey"})) {
        if (!v->isStr() || !IsHex(v->get_str())) {
            err = "destination_script must be hex";
            return false;
        }
        const auto raw = ParseHex(v->get_str());
        script = CScript(raw.begin(), raw.end());
        return true;
    }
    if (const UniValue* v = FindField(options, {"destination", "address"})) {
        if (!v->isStr()) {
            err = "destination must be a string";
            return false;
        }
        std::string dest_err;
        const CTxDestination dest = DecodeDestination(v->get_str(), dest_err);
        if (!IsValidDestination(dest)) {
            err = dest_err.empty() ? "destination is not a valid address" : dest_err;
            return false;
        }
        script = GetScriptForDestination(dest);
        return true;
    }
    err = "destination_script or destination required";
    return false;
}

bool ParsePrevout(const UniValue& options, COutPoint& prev, std::string& err)
{
    const UniValue* po = FindField(options, {"prevout"});
    std::string txid_hex;
    int64_t vout = 0;
    if (po && po->isObject()) {
        if (!(*po)["txid"].isStr() || !(*po)["vout"].isNum()) {
            err = "prevout needs txid and vout";
            return false;
        }
        txid_hex = (*po)["txid"].get_str();
        vout = (*po)["vout"].getInt<int64_t>();
    } else if (FindField(options, {"txid"}) && FindField(options, {"vout"})) {
        txid_hex = options["txid"].get_str();
        vout = options["vout"].getInt<int64_t>();
    } else {
        err = "prevout {txid,vout} required";
        return false;
    }
    const auto txid = Txid::FromHex(txid_hex);
    if (!txid) {
        err = "txid must be 32-byte hex";
        return false;
    }
    if (vout < 0 || vout > static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
        err = "vout out of range";
        return false;
    }
    prev = COutPoint(*txid, static_cast<uint32_t>(vout));
    return true;
}

UniValue FundingBase(const FrozenModelFunding& f, const CScript& script, const std::string& unsigned_hex,
                     const uint256& unsigned_txid)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 2);
    o.pushKV("frozen", true);
    o.pushKV("implemented", true);
    o.pushKV("automatic_spend", 0);
    o.pushKV("htlc", "htlc_sha256");
    if (!f.descriptor.empty()) o.pushKV("descriptor", f.descriptor);
    if (!f.key_hash_hex.empty()) o.pushKV("key_hash", f.key_hash_hex);
    if (!f.claimant.empty()) o.pushKV("claimant", f.claimant);
    if (!f.refund_pubkey.empty()) o.pushKV("refund_pubkey", f.refund_pubkey);
    if (f.refund_height > 0) o.pushKV("refund_height", static_cast<int64_t>(f.refund_height));
    if (f.amount_atoms > 0) o.pushKV("amount_atoms", f.amount_atoms);
    o.pushKV("max_atoms", f.max_atoms);
    if (!f.fingerprint.empty()) o.pushKV("fingerprint", f.fingerprint);
    if (!script.empty()) o.pushKV("output_script", HexStr(script));
    if (!unsigned_hex.empty()) o.pushKV("unsigned_hex", unsigned_hex);
    if (!unsigned_txid.IsNull()) o.pushKV("unsigned_txid", unsigned_txid.GetHex());
    o.pushKV("secrets", false);
    o.pushKV("note", "Helper never auto-spends. signmodelfunding then submitmodelfunding. Claim/refund via buildmodelhtlcclaim / buildmodelhtlcrefund (0.34.6 htlc_sha256).");
    return o;
}

bool Prepare(ModelCatalog& cat, const UniValue& params, UniValue& result, std::string& err_code, std::string& err)
{
    const UniValue& options = OptionsFromParams(params);
    if (!RejectForbiddenHtlc(options, err) || !RejectAutoPay(options, err)) {
        err_code = "INVALID_PARAMETER";
        return false;
    }
    FrozenModelFunding in;
    std::string release_id = FirstStringArg(params);
    if (const UniValue* v = FindField(options, {"release_id"})) release_id = v->get_str();
    if (options.exists("release_id") && options["release_id"].isStr()) release_id = options["release_id"].get_str();
    if (params.isArray() && params.size() > 0 && params[0].isStr()) release_id = params[0].get_str();

    if (const UniValue* v = FindField(options, {"key_hash"})) in.key_hash_hex = ToLower(v->get_str());
    if (const UniValue* v = FindField(options, {"claimant", "claimant_pubkey"})) in.claimant = v->get_str();
    if (const UniValue* v = FindField(options, {"refund_pubkey", "refund_key"})) in.refund_pubkey = v->get_str();
    if (const UniValue* v = FindField(options, {"descriptor"})) in.descriptor = v->get_str();
    if (const UniValue* v = FindField(options, {"refund_height"})) {
        if (!v->isNum()) {
            err_code = "INVALID_PARAMETER";
            err = "refund_height must be an integer";
            return false;
        }
        const int64_t h = v->getInt<int64_t>();
        if (h <= 0 || h > static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
            err_code = "INVALID_PARAMETER";
            err = "refund_height out of range";
            return false;
        }
        in.refund_height = static_cast<uint32_t>(h);
    }
    if (const UniValue* v = FindField(options, {"amount_atoms", "max_atoms"})) {
        if (!v->isNum()) {
            err_code = "INVALID_PARAMETER";
            err = "amount_atoms must be an integer";
            return false;
        }
        in.amount_atoms = v->getInt<int64_t>();
    }
    if (const UniValue* v = FindField(options, {"max_atoms"})) {
        if (v->isNum()) in.max_atoms = v->getInt<int64_t>();
    }
    if (in.max_atoms == 0) in.max_atoms = in.amount_atoms;

    std::vector<ReleaseCampaign> campaigns;
    LoadCampaigns(HelperRoot(cat), campaigns, err);
    MergeCampaign(campaigns, release_id, in);

    FrozenModelFunding frozen;
    if (!FreezeModelFunding(in, frozen, err)) {
        err_code = "INVALID_PARAMETER";
        if (err.empty()) err = "unable to freeze htlc_sha256 funding round";
        return false;
    }

    CScript script;
    std::string canonical;
    std::string expand_err;
    const std::string with_checksum = AddChecksum(frozen.descriptor);
    if (ExpandHtlcDescriptor(with_checksum, script, canonical, expand_err)) {
        frozen.descriptor = canonical;
    } else if (!in.descriptor.empty() && ExpandHtlcDescriptor(in.descriptor, script, canonical, expand_err)) {
        frozen.descriptor = canonical;
    } else if (const UniValue* v = FindField(options, {"output_script"})) {
        if (!v->isStr() || !IsHex(v->get_str())) {
            err_code = "INVALID_PARAMETER";
            err = "output_script must be hex";
            return false;
        }
        const auto raw = ParseHex(v->get_str());
        script = CScript(raw.begin(), raw.end());
    }

    std::string unsigned_hex;
    uint256 unsigned_txid;
    int64_t fee_atoms = 0;
    int64_t fee_cap = 0;
    if (const UniValue* v = FindField(options, {"fee_cap_atoms"})) {
        if (v->isNum()) fee_cap = v->getInt<int64_t>();
        if (fee_cap < 0) {
            err_code = "INVALID_PARAMETER";
            err = "fee_cap_atoms must not be negative";
            return false;
        }
    }
    if (FindField(options, {"inputs"})) {
        if (script.empty()) {
            err_code = "INVALID_PARAMETER";
            err = expand_err.empty() ? "HTLC output_script required to assemble unsigned_hex" : expand_err;
            return false;
        }
        CMutableTransaction mtx;
        mtx.version = 2;
        int64_t in_sum = 0;
        if (!ParseInputs(options["inputs"], mtx, in_sum, err)) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        mtx.vout.emplace_back(frozen.amount_atoms, script);
        if (in_sum > 0) {
            const int64_t change = in_sum - frozen.amount_atoms;
            if (change < 0) {
                err_code = "INVALID_PARAMETER";
                err = "inputs do not cover amount_atoms";
                return false;
            }
            fee_atoms = change;
            if (const UniValue* v = FindField(options, {"fee_atoms"})) {
                if (v->isNum()) fee_atoms = v->getInt<int64_t>();
            }
            if (fee_atoms < 0 || fee_atoms > change) {
                err_code = "INVALID_PARAMETER";
                err = "fee_atoms exceeds input surplus";
                return false;
            }
            const int64_t change_out = in_sum - frozen.amount_atoms - fee_atoms;
            CScript change_script;
            std::string ch_err;
            if (change_out > 0) {
                if (FindField(options, {"change_script", "change_destination", "destination", "destination_script"})) {
                    if (!DestinationScript(options, change_script, ch_err)) {
                        err_code = "INVALID_PARAMETER";
                        err = ch_err;
                        return false;
                    }
                    mtx.vout.emplace_back(change_out, change_script);
                }
            }
        }
        if (fee_cap > 0 && fee_atoms > fee_cap) {
            err_code = "INVALID_PARAMETER";
            err = strprintf("funding fee %d exceeds fee_cap_atoms %d", fee_atoms, fee_cap);
            return false;
        }
        unsigned_hex = EncodeHexTx(CTransaction(mtx));
        unsigned_txid = mtx.GetHash().ToUint256();
    }

    result = FundingBase(frozen, script, unsigned_hex, unsigned_txid);
    if (!release_id.empty()) result.pushKV("release_id", release_id);
    result.pushKV("fee_cap_atoms", fee_cap);
    result.pushKV("fee_atoms", fee_atoms);
    return true;
}

bool Sign(const UniValue& params, UniValue& result, std::string& err_code, std::string& err)
{
    const UniValue& options = OptionsFromParams(params);
    if (!RejectForbiddenHtlc(options, err) || !RejectAutoPay(options, err)) {
        err_code = "INVALID_PARAMETER";
        return false;
    }
    std::string hex = HexArg(options, params, {"hex", "unsigned_hex", "signed_hex"});
    if (hex.empty() && params.isArray() && params.size() > 0 && params[0].isStr()) hex = params[0].get_str();
    if (hex.empty()) {
        err_code = "INVALID_PARAMETER";
        err = "hex required";
        return false;
    }
    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, hex, /*try_no_witness=*/true, /*try_witness=*/true)) {
        err_code = "INVALID_PARAMETER";
        err = "TX decode failed. Make sure the hex is a serialized transaction.";
        return false;
    }
    if (mtx.vout.empty()) {
        err_code = "INVALID_PARAMETER";
        err = "funding transaction has no outputs";
        return false;
    }
    if ((FindField(options, {"unsigned_txid"}) || FindField(options, {"output_script"})) &&
        !MatchFrozen(options, mtx, err)) {
        err_code = "INVALID_PARAMETER";
        return false;
    }
    const bool complete = InputsFullySigned(mtx);
    result = UniValue(UniValue::VOBJ);
    result.pushKV("schema_version", 2);
    result.pushKV("implemented", true);
    result.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
    result.pushKV("complete", complete);
    result.pushKV("txid", mtx.GetHash().GetHex());
    result.pushKV("frozen", true);
    result.pushKV("automatic_spend", 0);
    result.pushKV("htlc", "htlc_sha256");
    result.pushKV("wallet", false);
    if (!complete) {
        result.pushKV("note", "Helper has no spending keys; pass a signed hex or sign with btxd wallet signmodelfunding.");
    }
    return true;
}

bool Submit(ModelCatalog& cat, const UniValue& params, UniValue& result, std::string& err_code, std::string& err)
{
    const UniValue& options = OptionsFromParams(params);
    if (!RejectForbiddenHtlc(options, err) || !RejectAutoPay(options, err)) {
        err_code = "INVALID_PARAMETER";
        return false;
    }
    std::string hex = HexArg(options, params, {"hex", "unsigned_hex", "signed_hex"});
    if (hex.empty() && params.isArray() && params.size() > 0 && params[0].isStr()) hex = params[0].get_str();
    if (hex.empty()) {
        err_code = "INVALID_PARAMETER";
        err = "hex required";
        return false;
    }
    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, hex, /*try_no_witness=*/true, /*try_witness=*/true)) {
        err_code = "INVALID_PARAMETER";
        err = "TX decode failed. Make sure the hex is a serialized transaction.";
        return false;
    }
    if ((FindField(options, {"unsigned_txid"}) || FindField(options, {"output_script"})) &&
        !MatchFrozen(options, mtx, err)) {
        err_code = "INVALID_PARAMETER";
        return false;
    }
    const std::string txid = mtx.GetHash().GetHex();
    std::vector<Quote> quotes;
    std::vector<PaymentJournal> journal;
    const fs::path dir = HelperRoot(cat);
    LoadPaymentState(dir, quotes, journal, err);
    const bool duplicate = DuplicatePayment(journal, txid);
    if (!duplicate) {
        PaymentJournal e;
        e.txid = txid;
        e.accepted = true;
        if (const UniValue* v = FindField(options, {"quote_id"})) e.quote_id = v->get_str();
        journal.push_back(e);
        if (!SavePaymentState(dir, quotes, journal, err)) {
            err_code = "IO";
            return false;
        }
    }
    result = UniValue(UniValue::VOBJ);
    result.pushKV("schema_version", 2);
    result.pushKV("implemented", true);
    result.pushKV("txid", txid);
    result.pushKV("submitted", !duplicate);
    result.pushKV("duplicate", duplicate);
    result.pushKV("broadcast", false);
    result.pushKV("paid_chain_verify", false);
    result.pushKV("automatic_spend", 0);
    result.pushKV("htlc", "htlc_sha256");
    result.pushKV("note", "Journaled locally. Helper does not broadcast; btxd submitmodelfunding broadcasts.");
    return true;
}

bool ExportRecovery(ModelCatalog& cat, const UniValue& params, UniValue& result, std::string& err_code, std::string& err)
{
    const UniValue& options = OptionsFromParams(params);
    if (!RejectForbiddenHtlc(options, err) || !RejectAutoPay(options, err)) {
        err_code = "INVALID_PARAMETER";
        return false;
    }
    FrozenModelFunding in;
    std::string release_id = FirstStringArg(params);
    if (const UniValue* v = FindField(options, {"release_id"})) release_id = v->get_str();
    if (const UniValue* v = FindField(options, {"key_hash"})) in.key_hash_hex = ToLower(v->get_str());
    if (const UniValue* v = FindField(options, {"claimant", "claimant_pubkey"})) in.claimant = v->get_str();
    if (const UniValue* v = FindField(options, {"refund_pubkey", "refund_key"})) in.refund_pubkey = v->get_str();
    if (const UniValue* v = FindField(options, {"descriptor"})) in.descriptor = v->get_str();
    if (const UniValue* v = FindField(options, {"refund_height"})) {
        if (v->isNum()) {
            const int64_t h = v->getInt<int64_t>();
            if (h > 0 && h <= static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
                in.refund_height = static_cast<uint32_t>(h);
            }
        }
    }
    in.amount_atoms = 1;
    in.max_atoms = 1;
    std::vector<ReleaseCampaign> campaigns;
    LoadCampaigns(HelperRoot(cat), campaigns, err);
    MergeCampaign(campaigns, release_id, in);
    FrozenModelFunding frozen;
    if (in.descriptor.empty() && !in.key_hash_hex.empty() && !in.claimant.empty() &&
        !in.refund_pubkey.empty() && in.refund_height > 0) {
        if (!FreezeModelFunding(in, frozen, err)) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
    } else {
        frozen = in;
        if (frozen.descriptor.empty() && !in.key_hash_hex.empty() && !in.claimant.empty() &&
            !in.refund_pubkey.empty() && in.refund_height > 0) {
            frozen.descriptor = HtlcSha256Descriptor(ToLower(in.key_hash_hex), in.claimant, in.refund_height, in.refund_pubkey);
        }
    }
    CScript script;
    std::string canonical;
    std::string expand_err;
    if (!frozen.descriptor.empty()) {
        (void)ExpandHtlcDescriptor(frozen.descriptor, script, canonical, expand_err);
        if (!canonical.empty()) frozen.descriptor = canonical;
    }
    result = UniValue(UniValue::VOBJ);
    result.pushKV("schema_version", 2);
    result.pushKV("implemented", true);
    if (!release_id.empty()) result.pushKV("release_id", release_id);
    if (!frozen.descriptor.empty()) result.pushKV("descriptor", frozen.descriptor);
    if (!frozen.key_hash_hex.empty()) result.pushKV("key_hash", frozen.key_hash_hex);
    if (frozen.refund_height > 0) result.pushKV("refund_height", static_cast<int64_t>(frozen.refund_height));
    if (!script.empty()) result.pushKV("output_script", HexStr(script));
    if (!frozen.claimant.empty()) result.pushKV("claimant", frozen.claimant);
    if (!frozen.refund_pubkey.empty()) result.pushKV("refund_pubkey", frozen.refund_pubkey);
    result.pushKV("automatic_spend", 0);
    result.pushKV("htlc", "htlc_sha256");
    result.pushKV("secrets", false);
    result.pushKV("wallet_seed", false);
    result.pushKV("service_sk", false);
    result.pushKV("use_claim", "buildmodelhtlcclaim");
    result.pushKV("use_refund", "buildmodelhtlcrefund");
    result.pushKV("note", "Public recovery material only. HASH160 htlc_tx is recovery-only and is not selected.");
    if (frozen.descriptor.empty() && frozen.key_hash_hex.empty()) {
        result.pushKV("error", "no public recovery material; pass descriptor/key_hash or a known release_id");
    }
    return true;
}

bool BuildClaimOrRefund(const std::string& method, const UniValue& params, UniValue& result,
                        std::string& err_code, std::string& err)
{
    const UniValue& options = OptionsFromParams(params);
    if (!RejectForbiddenHtlc(options, err) || !RejectAutoPay(options, err)) {
        err_code = "INVALID_PARAMETER";
        return false;
    }
    const bool claim = method == "buildmodelhtlcclaim";
    FrozenModelFunding in;
    if (const UniValue* v = FindField(options, {"key_hash"})) in.key_hash_hex = ToLower(v->get_str());
    if (const UniValue* v = FindField(options, {"claimant", "claimant_pubkey"})) in.claimant = v->get_str();
    if (const UniValue* v = FindField(options, {"refund_pubkey", "refund_key"})) in.refund_pubkey = v->get_str();
    if (const UniValue* v = FindField(options, {"descriptor"})) in.descriptor = v->get_str();
    if (const UniValue* v = FindField(options, {"refund_height"})) {
        if (v->isNum()) {
            const int64_t h = v->getInt<int64_t>();
            if (h > 0 && h <= static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
                in.refund_height = static_cast<uint32_t>(h);
            }
        }
    }
    if (in.descriptor.empty() && !in.key_hash_hex.empty() && !in.claimant.empty() &&
        !in.refund_pubkey.empty() && in.refund_height > 0) {
        in.descriptor = HtlcSha256Descriptor(ToLower(in.key_hash_hex), in.claimant, in.refund_height, in.refund_pubkey);
    }
    if (in.descriptor.empty()) {
        err_code = "INVALID_PARAMETER";
        err = claim ? "descriptor or key_hash+claimant+refund_pubkey+refund_height required"
                     : "descriptor or refund terms required";
        return false;
    }
    if (ContainsForbiddenHtlcToken(in.descriptor)) {
        err_code = "INVALID_PARAMETER";
        err = "HASH160 htlc_tx is recovery-only; model funding uses htlc_sha256";
        return false;
    }

    if (claim) {
        std::string preimage_hex;
        if (const UniValue* v = FindField(options, {"preimage", "preimage_hex"})) {
            if (v->isStr()) preimage_hex = v->get_str();
        }
        if (preimage_hex.empty()) {
            err_code = "INVALID_PARAMETER";
            err = "preimage required (SHA-256 must equal key_hash)";
            return false;
        }
        const auto preimage = TryParseHex<unsigned char>(preimage_hex);
        if (!preimage || preimage->empty()) {
            err_code = "INVALID_PARAMETER";
            err = "preimage must be hex";
            return false;
        }
        const Hash32 got = Sha256(*preimage);
        std::string want = in.key_hash_hex;
        if (want.empty()) {
            const auto pos = in.descriptor.find("htlc_sha256(");
            if (pos != std::string::npos) {
                const auto start = pos + 12;
                const auto comma = in.descriptor.find(',', start);
                if (comma != std::string::npos) want = ToLower(in.descriptor.substr(start, comma - start));
            }
        }
        if (want.empty() || got.Hex() != ToLower(want)) {
            err_code = "PREIMAGE_MISMATCH";
            err = "SHA-256(preimage) does not match key_hash";
            return false;
        }
        result.pushKV("key_hash", got.Hex());
        result.pushKV("preimage_checked", true);
    } else if (in.refund_height == 0) {
        err_code = "INVALID_PARAMETER";
        err = "refund_height required";
        return false;
    }

    COutPoint prev;
    if (!ParsePrevout(options, prev, err)) {
        err_code = "INVALID_PARAMETER";
        return false;
    }
    CScript dest;
    if (!DestinationScript(options, dest, err)) {
        err_code = "INVALID_PARAMETER";
        return false;
    }
    int64_t amount = 0;
    if (const UniValue* v = FindField(options, {"amount_atoms", "amount"})) {
        if (!v->isNum()) {
            err_code = "INVALID_PARAMETER";
            err = "amount_atoms must be an integer";
            return false;
        }
        amount = v->getInt<int64_t>();
    }
    if (amount <= 0) {
        err_code = "INVALID_PARAMETER";
        err = "amount_atoms must be positive";
        return false;
    }
    int64_t fee = 0;
    if (const UniValue* v = FindField(options, {"fee", "fee_atoms"})) {
        if (v->isNum()) fee = v->getInt<int64_t>();
    }
    if (fee < 0 || fee >= amount) {
        err_code = "INVALID_PARAMETER";
        err = "fee must be non-negative and less than amount_atoms";
        return false;
    }

    CMutableTransaction mtx;
    mtx.version = 2;
    uint32_t sequence = CTxIn::SEQUENCE_FINAL;
    if (claim) {
        mtx.nLockTime = 0;
    } else {
        mtx.nLockTime = in.refund_height;
        sequence = CTxIn::SEQUENCE_FINAL - 1;
    }
    mtx.vin.emplace_back(prev, CScript(), sequence);
    mtx.vout.emplace_back(amount - fee, dest);

    result.pushKV("schema_version", 2);
    result.pushKV("implemented", true);
    result.pushKV("complete", false);
    result.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
    result.pushKV("txid", mtx.GetHash().GetHex());
    result.pushKV("selected_path", claim ? "claim" : "refund");
    result.pushKV("htlc", "htlc_sha256");
    result.pushKV("descriptor", in.descriptor);
    result.pushKV("automatic_spend", 0);
    result.pushKV("wallet", false);
    result.pushKV("use", claim ? "buildhtlcclaim" : "buildhtlcrefund");
    result.pushKV("note", "Unsigned 0.34.6 htlc_sha256 template. Helper has no claimer/refund keys; complete=false. HASH160 htlc_tx is recovery-only.");
    return true;
}

} // namespace

bool DispatchFundingRpc(ModelCatalog& cat, const std::string& method, const UniValue& params,
                         UniValue& result, std::string& err_code, std::string& err)
{
    if (method == "preparemodelfunding") return Prepare(cat, params, result, err_code, err);
    if (method == "signmodelfunding") return Sign(params, result, err_code, err);
    if (method == "submitmodelfunding") return Submit(cat, params, result, err_code, err);
    if (method == "exportmodelrecovery") return ExportRecovery(cat, params, result, err_code, err);
    if (method == "buildmodelhtlcclaim" || method == "buildmodelhtlcrefund") {
        return BuildClaimOrRefund(method, params, result, err_code, err);
    }
    return false;
}

} // namespace modelnet
