// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/hcp.h>

#include <modelnet/capability_types.h>
#include <modelnet/identity.h>
#include <modelnet/package_pjson.h>
#include <consensus/amount.h>
#include <crypto/common.h>
#include <crypto/sha256.h>
#include <crypto/sha384.h>
#include <util/strencodings.h>

#include <cctype>
#include <cstring>
#include <limits>

namespace modelnet {

namespace {

const char* kTypes[] = {
    HCP_TYPE_PROVIDER_PROFILE,
    HCP_TYPE_CAPABILITY_OFFER,
    HCP_TYPE_FUNDING_QUOTE,
    HCP_TYPE_FINANCE_INTENT,
    HCP_TYPE_FINANCIAL_RECEIPT,
    HCP_TYPE_CAPABILITY_HANDOFF,
    HCP_TYPE_LOCAL_READINESS,
    HCP_TYPE_RESERVE_EXTENSION,
    HCP_TYPE_ENTITY_LINK,
    HCP_TYPE_PORTFOLIO,
    HCP_TYPE_RESERVE_POLICY,
    HCP_TYPE_RESERVE_SNAPSHOT,
    HCP_TYPE_WORKLOAD,
    HCP_TYPE_TCO,
    HCP_TYPE_CAPITAL_PLAN,
    HCP_TYPE_ALLOCATION,
    HCP_TYPE_APPROVAL_RULE,
    HCP_TYPE_APPROVAL_REQUEST,
    HCP_TYPE_APPROVAL_DECISION,
    HCP_TYPE_CAPABILITY_POSITION,
    HCP_TYPE_RESEARCH_PROGRAM,
    HCP_TYPE_PROGRAM_MEMBERSHIP,
    HCP_TYPE_PRODUCT_OFFER,
    HCP_TYPE_CAPITAL_EXECUTION,
    HCP_TYPE_RESERVE_REPORT,
    HCP_TYPE_LAYER_EXTENSION,
    HCP_TYPE_PROVIDER_ROLE,
    HCP_TYPE_SERVICE_BINDING,
    HCP_TYPE_ADAPTER_CAPABILITY,
    HCP_TYPE_INSTITUTIONAL_ASSET,
    HCP_TYPE_ASSET_RIGHTS,
    HCP_TYPE_POSITION_OBS,
    HCP_TYPE_VALUATION_OBS,
    HCP_TYPE_EXPOSURE_LINK,
    HCP_TYPE_PORTFOLIO_PROJECTION,
    HCP_TYPE_METRIC_DEFINITION,
    HCP_TYPE_EXPORT_MANIFEST,
    HCP_TYPE_IMPORT_MANIFEST,
    HCP_TYPE_RECONCILIATION_BREAK,
    HCP_TYPE_PORTFOLIO_INSTRUCTION,
    HCP_TYPE_SCENARIO_RESULT,
    HCP_TYPE_LAYER_CONFORMANCE,
    HCP_TYPE_LAYER_JOB,
    HCP_TYPE_ADAPTER_CAPABILITY_MANIFEST,
    HCP_TYPE_INSTITUTIONAL_ASSET_RECORD,
    HCP_TYPE_RIGHTS_STATEMENT,
    HCP_TYPE_INTEROP_RECEIPT,
    HCP_TYPE_SCENARIO_DEFINITION,
    HCP_TYPE_SCENARIO_RESULT_SPEC,
    HCP_TYPE_CONFORMANCE_STATEMENT,
};

const char* kForbidden[] = {
    "shell", "command", "exec", "cwd", "ld_preload", "LD_PRELOAD", "wget", "curl",
    "env", "environment_vars", "bash", "powershell", "cmd", "runtime_url",
    "executable_url", "install_script", "wallet_rpc", "automatic_spend_atoms",
    "skip_verification", "disable_verification", "skip_hash", "skip_hash_checks",
    "installer_key", "software_trust_root", "trust_root",
};

bool ObjectTypeChars(const std::string& t)
{
    if (t.empty() || t.size() > 64) return false;
    if (!std::isalpha(static_cast<unsigned char>(t[0]))) return false;
    for (char c : t) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (!(std::isalnum(u) || c == '_')) return false;
    }
    return true;
}

} // namespace

bool HcpObjectTypeOk(const std::string& t)
{
    for (const char* x : kTypes) {
        if (t == x) return true;
    }
    return false;
}

std::string HcpDomain(const std::string& object_type)
{
    return std::string(HCP_DOMAIN_PREFIX) + object_type + HCP_DOMAIN_SUFFIX;
}

bool ParseAtomString(const std::string& s, int64_t& out, std::string& err)
{
    out = 0;
    if (s.empty() || (s.size() > 1 && s[0] == '0') || s[0] == '+' || s[0] == '-') {
        err = HCP_ERR_ATOM_ENCODING;
        return false;
    }
    if (s.find('.') != std::string::npos || s.find('e') != std::string::npos || s.find('E') != std::string::npos) {
        err = HCP_ERR_ATOM_ENCODING;
        return false;
    }
    for (char c : s) {
        if (c < '0' || c > '9') {
            err = HCP_ERR_ATOM_ENCODING;
            return false;
        }
    }
    if (s.size() > 19) {
        err = "AMOUNT_RANGE";
        return false;
    }
    try {
        out = std::stoll(s, nullptr, 10);
    } catch (...) {
        err = "AMOUNT_RANGE";
        return false;
    }
    if (out < 0 || !MoneyRange(out)) {
        err = "AMOUNT_RANGE";
        return false;
    }
    return true;
}

bool FormatAtomString(int64_t n, std::string& out)
{
    if (n < 0 || !MoneyRange(n)) return false;
    out = std::to_string(n);
    return true;
}

bool HcpCanonicalBody(const UniValue& body, std::vector<unsigned char>& out, std::string& err)
{
    out.clear();
    if (!body.isObject()) {
        err = "body must be object";
        return false;
    }
    if (!EncodePjson1(body, out, err)) return false;
    if (static_cast<int64_t>(out.size()) > HCP_MAX_BODY_BYTES) {
        err = "BODY_TOO_LARGE";
        return false;
    }
    return true;
}

bool HcpBodyId(const std::string& object_type, const UniValue& body, Digest48& out, std::string& err)
{
    out = {};
    if (!ObjectTypeChars(object_type)) {
        err = "OBJECT_TYPE";
        return false;
    }
    std::vector<unsigned char> canon;
    if (!HcpCanonicalBody(body, canon, err)) return false;
    return CapabilityObjectId(HcpDomain(object_type), Span<const unsigned char>{canon.data(), canon.size()}, out, err);
}

bool HcpAmountsOk(const UniValue& amounts, int64_t& total, std::string& err)
{
    total = 0;
    if (!amounts.isObject()) {
        err = HCP_ERR_ATOM_ENCODING;
        return false;
    }
    static const char* keys[] = {"principal_atoms", "network_fee_cap_atoms", "service_fee_atoms", "tax_atoms"};
    int64_t sum = 0;
    for (const char* k : keys) {
        if (!amounts.exists(k) || !amounts[k].isStr()) {
            err = HCP_ERR_ATOM_ENCODING;
            return false;
        }
        int64_t n = 0;
        if (!ParseAtomString(amounts[k].get_str(), n, err)) return false;
        if (sum > std::numeric_limits<int64_t>::max() - n) {
            err = "AMOUNT_RANGE";
            return false;
        }
        sum += n;
    }
    if (!amounts.exists("max_total_debit_atoms") || !amounts["max_total_debit_atoms"].isStr()) {
        err = HCP_ERR_ATOM_ENCODING;
        return false;
    }
    int64_t cap = 0;
    if (!ParseAtomString(amounts["max_total_debit_atoms"].get_str(), cap, err)) return false;
    if (sum != cap) {
        err = "TOTAL_MISMATCH";
        return false;
    }
    total = sum;
    return true;
}

bool HcpRejectForbiddenFields(const UniValue& body, std::string& err)
{
    if (!body.isObject()) {
        err = "SCHEMA";
        return false;
    }
    for (const auto& k : body.getKeys()) {
        for (const char* f : kForbidden) {
            if (k == f) {
                err = "FORBIDDEN_FIELD";
                return false;
            }
        }
        if (body[k].isObject() && !HcpRejectForbiddenFields(body[k], err)) return false;
        if (body[k].isArray()) {
            for (const auto& e : body[k].getValues()) {
                if (e.isObject() && !HcpRejectForbiddenFields(e, err)) return false;
            }
        }
        if (body[k].isStr()) {
            const std::string& v = body[k].get_str();
            if (v.find("curl ") != std::string::npos || v.find("| sh") != std::string::npos ||
                v.find("walletpassphrase") != std::string::npos) {
                err = "FORBIDDEN_FIELD";
                return false;
            }
        }
    }
    return true;
}

bool ParseHcpEnvelope(const UniValue& obj, HcpEnvelope& out, std::string& err)
{
    out = {};
    if (!obj.isObject()) {
        err = "envelope object";
        return false;
    }
    if (!obj.exists("object_type") || !obj["object_type"].isStr()) {
        err = "OBJECT_TYPE";
        return false;
    }
    out.object_type = obj["object_type"].get_str();
    if (!HcpObjectTypeOk(out.object_type) || !ObjectTypeChars(out.object_type)) {
        err = "OBJECT_TYPE";
        return false;
    }
    if (!obj.exists("body") || !obj["body"].isObject()) {
        err = "body";
        return false;
    }
    out.body = obj["body"];
    if (!HcpRejectForbiddenFields(out.body, err)) return false;
    Digest48 id;
    if (!HcpBodyId(out.object_type, out.body, id, err)) return false;
    out.body_id = id;
    if (obj.exists("body_id") && obj["body_id"].isStr()) {
        Digest48 claimed;
        if (!Digest48::FromHex(obj["body_id"].get_str(), claimed, err)) return false;
        if (claimed != id) {
            err = HCP_ERR_BODY_ID_MISMATCH;
            return false;
        }
    }
    if (obj.exists("signer_key_id") && obj["signer_key_id"].isStr()) {
        out.signer_key_id = obj["signer_key_id"].get_str();
    }
    if (obj.exists("signature") && !obj["signature"].isNull()) {
        if (!obj["signature"].isStr()) {
            err = "signature";
            return false;
        }
        auto sig = TryParseHex<unsigned char>(obj["signature"].get_str());
        if (!sig || sig->empty()) {
            err = "signature";
            return false;
        }
        out.signature = std::move(*sig);
        out.signature_present = true;
    }
    return true;
}

UniValue EncodeHcpEnvelope(const HcpEnvelope& env)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("object_type", env.object_type);
    o.pushKV("body", env.body);
    o.pushKV("body_id", env.body_id.Hex());
    o.pushKV("signer_key_id", env.signer_key_id);
    if (env.signature_present) {
        o.pushKV("signature", HexStr(env.signature));
    } else {
        o.pushKV("signature", UniValue());
    }
    return o;
}

bool HcpSign(HcpEnvelope& env, Span<const unsigned char> sk, const std::string& key_id, std::string& err)
{
    if (!HcpBodyId(env.object_type, env.body, env.body_id, err)) return false;
    if (!SignMlDsa44(sk, Span<const unsigned char>{env.body_id.data.data(), Digest48::SIZE}, env.signature, err)) {
        return false;
    }
    env.signer_key_id = key_id;
    env.signature_present = true;
    return true;
}

bool HcpVerify(const HcpEnvelope& env, Span<const unsigned char> pk, std::string& err)
{
    Digest48 id;
    if (!HcpBodyId(env.object_type, env.body, id, err)) return false;
    if (id != env.body_id) {
        err = HCP_ERR_BODY_ID_MISMATCH;
        return false;
    }
    if (!env.signature_present) {
        err = "unsigned";
        return false;
    }
    if (pk.size() != MLDSA44_PK) {
        err = "SIGNATURE_INVALID";
        return false;
    }
    if (!VerifyMlDsa44(pk, Span<const unsigned char>{env.body_id.data.data(), Digest48::SIZE},
                        Span<const unsigned char>{env.signature.data(), env.signature.size()})) {
        err = "SIGNATURE_INVALID";
        return false;
    }
    return true;
}

bool HcpEnvelopeFromBytes(Span<const unsigned char> raw, HcpEnvelope& out, std::string& err)
{
    UniValue parsed;
    if (!DecodePjson1(raw, parsed, err)) return false;
    return ParseHcpEnvelope(parsed, out, err);
}

bool HcpIsPublicReadPath(const std::string& method, const std::string& path)
{
    if (method != "GET" && method != "HEAD") return false;
    return path == "/profile" || path.rfind("/packages/", 0) == 0 || path.rfind("/economy/", 0) == 0;
}

bool HcpSha384DigestUsable(const std::string& hex)
{
    if (hex.size() != 96) return false;
    bool filler = true;
    const char first = hex[0];
    for (char c : hex) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        if (c != first) filler = false;
    }
    return !filler;
}

void HcpApplyNegotiatedDigests(UniValue& body, const std::string& schema_digest, const std::string& operations_digest)
{
    if (HcpSha384DigestUsable(schema_digest) && HcpSha384DigestUsable(operations_digest) &&
        schema_digest != operations_digest) {
        body.pushKV("schema_digest", schema_digest);
        body.pushKV("operations_digest", operations_digest);
        body.pushKV("digests_available", true);
        body.pushKV("negotiated", true);
        return;
    }
    body.pushKV("schema_digest", UniValue());
    body.pushKV("operations_digest", UniValue());
    body.pushKV("digests_available", false);
    body.pushKV("negotiated", false);
    body.pushKV("negotiation_unavailable_reason", "schema_and_operations_digests_not_computed");
}

HcpConfig HcpWalletlessPreset()
{
    HcpConfig c;
    c.walletless = true;
    c.start_wallet = false;
    c.start_mining = false;
    c.finance_enabled = false;
    c.expose_runtime_to_gateway = false;
    c.reporting_default_off = true;
    c.automatic_spend_atoms = 0;
    c.custody_backend = HCP_CUSTODY_DISABLED;
    c.enabled_profiles = {HCP_PROFILE_DISCOVERY, HCP_PROFILE_HANDOFF};
    return c;
}

HcpConfig HcpFundingLabPreset()
{
    HcpConfig c = HcpWalletlessPreset();
    c.walletless = false;
    c.finance_enabled = true;
    c.custody_backend = HCP_CUSTODY_BTX_NATIVE;
    c.enabled_profiles = {HCP_PROFILE_DISCOVERY, HCP_PROFILE_HANDOFF, HCP_PROFILE_CUSTODY, HCP_PROFILE_FUNDING,
                           HCP_PROFILE_FLEET};
    c.cr11_enabled = true;
    c.cr12_enabled = true;
    return c;
}

bool HcpHttpResponse::CachePrivate() const
{
    auto it = headers.find("Cache-Control");
    return it != headers.end() && it->second.find("no-store") != std::string::npos;
}

} // namespace modelnet
