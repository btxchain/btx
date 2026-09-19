// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/package_core.h>

#include <modelnet/capability_types.h>
#include <modelnet/identity.h>
#include <modelnet/package_documents.h>
#include <modelnet/package_pjson.h>
#include <crypto/common.h>
#include <crypto/sha384.h>
#include <span.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace modelnet {
namespace {

const std::set<std::string> kPayloadRequired{"core", "observations", "signatures"};
const std::set<std::string> kCoreV2Required{
    "version", "network", "package_type", "label", "resources", "critical_extensions", "documents", "agent_handoff"};
const std::set<std::string> kCoreV2Allowed{
    "version",         "network",     "package_type", "label",      "resources", "critical_extensions",
    "documents",       "agent_handoff", "variants",     "economy_refs", "source_hints"};
const std::set<std::string> kNetworks{"MAINNET", "TESTNET", "REGTEST"};
const std::set<std::string> kPackageTypes{"MODEL", "COLLECTION", "RELEASE", "BOUNTY", "VARIANT_INDEX"};
const std::set<std::string> kResourceKinds{"MODEL", "ARTIFACT", "COLLECTION", "RELEASE", "BOUNTY"};
const std::set<std::string> kCritical{"AGENT_HANDOFF_V1"};

bool Fail(std::string& err_code, std::string& err, const char* code, const std::string& msg)
{
    err_code = code;
    err = msg.empty() ? code : msg;
    return false;
}

void SetErr(DecodedBtxPackage& out, const char* code, const std::string& msg, std::string& err_out)
{
    out.err_code = code;
    err_out = msg.empty() ? code : msg;
}

bool ExactKeys(const UniValue& value, const std::set<std::string>& required, const std::set<std::string>& allowed,
               const char* where, std::string& err_code, std::string& err)
{
    if (!value.isObject()) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", std::string(where) + ": object required");
    }
    for (const auto& k : value.getKeys()) {
        if (!allowed.count(k)) {
            return Fail(err_code, err, "NONCANONICAL_PAYLOAD", std::string(where) + ": unknown field");
        }
    }
    for (const auto& k : required) {
        if (!value.exists(k)) {
            return Fail(err_code, err, "NONCANONICAL_PAYLOAD", std::string(where) + ": missing required field");
        }
    }
    return true;
}

bool ValidDigestField(const UniValue& v, std::string& err_code, std::string& err)
{
    if (!v.isStr()) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "invalid SHA-384 digest");
    }
    Digest48 d;
    std::string hexerr;
    if (!Digest48::FromHex(v.get_str(), d, hexerr)) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "invalid SHA-384 digest");
    }
    return true;
}

bool UnsignedDecimal(const UniValue& v, uint64_t& n, std::string& err_code, std::string& err)
{
    if (!v.isStr()) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "noncanonical decimal string");
    }
    const std::string& s = v.get_str();
    if (s.empty() || s.size() > 20 || (s.size() > 1 && s[0] == '0')) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "noncanonical decimal string");
    }
    n = 0;
    for (char c : s) {
        if (c < '0' || c > '9') {
            return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "noncanonical decimal string");
        }
        const uint64_t d = static_cast<uint64_t>(c - '0');
        if (n > (std::numeric_limits<uint64_t>::max() - d) / 10) {
            return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "uint64 overflow");
        }
        n = n * 10 + d;
    }
    return true;
}

bool SafeText(const UniValue& v, const char* where, std::string& err_code, std::string& err)
{
    if (!v.isStr()) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", std::string(where) + ": string required");
    }
    const std::string& s = v.get_str();
    const auto* p = reinterpret_cast<const unsigned char*>(s.data());
    const auto* end = p + s.size();
    while (p < end) {
        uint32_t cp = 0;
        if (*p <= 0x7f) {
            cp = *p++;
        } else {
            int need = 0;
            if ((*p & 0xe0) == 0xc0) {
                need = 1;
                cp = *p & 0x1f;
            } else if ((*p & 0xf0) == 0xe0) {
                need = 2;
                cp = *p & 0x0f;
            } else if ((*p & 0xf8) == 0xf0) {
                need = 3;
                cp = *p & 0x07;
            } else {
                return Fail(err_code, err, "NONCANONICAL_PAYLOAD", std::string(where) + ": invalid UTF-8");
            }
            ++p;
            for (int i = 0; i < need; ++i) {
                if (p >= end || (*p & 0xc0) != 0x80) {
                    return Fail(err_code, err, "NONCANONICAL_PAYLOAD", std::string(where) + ": invalid UTF-8");
                }
                cp = (cp << 6) | (*p & 0x3f);
                ++p;
            }
        }
        if (cp < 32 || (cp >= 0x7f && cp < 0xa0) || cp == 0x061c || cp == 0x200e || cp == 0x200f ||
            (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) {
            return Fail(err_code, err, "NONCANONICAL_PAYLOAD",
                        std::string(where) + ": controls or directional formatting");
        }
    }
    return true;
}

bool InSet(const UniValue& v, const std::set<std::string>& allowed, const char* where, std::string& err_code,
           std::string& err)
{
    if (!v.isStr() || !allowed.count(v.get_str())) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", where);
    }
    return true;
}

bool ValidateResources(const UniValue& resources, std::map<std::string, UniValue>& ids, std::string& err_code,
                       std::string& err)
{
    if (!resources.isArray() || resources.size() > 256) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "resource count");
    }
    const std::set<std::string> req{"kind", "id"};
    const std::set<std::string> allow{"kind",  "id",    "uri",   "manifest_id", "size_bytes",
                                      "format", "label", "dependencies"};
    for (const auto& r : resources.getValues()) {
        if (!ExactKeys(r, req, allow, "resource", err_code, err)) return false;
        if (!InSet(r["kind"], kResourceKinds, "resource kind", err_code, err)) return false;
        if (!ValidDigestField(r["id"], err_code, err)) return false;
        const std::string id = r["id"].get_str();
        if (ids.count(id)) {
            return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "duplicate resource id");
        }
        if (r.exists("manifest_id") && !ValidDigestField(r["manifest_id"], err_code, err)) return false;
        if (r.exists("size_bytes")) {
            uint64_t n = 0;
            if (!UnsignedDecimal(r["size_bytes"], n, err_code, err)) return false;
        }
        if (r.exists("uri")) {
            if (!r["uri"].isStr() || r["uri"].get_str().rfind("btx://", 0) != 0) {
                return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "URI shape; native decoder still required");
            }
        }
        ids.emplace(id, r);
    }
    std::map<std::string, int> heights;
    std::set<std::string> active;
    auto height = [&](auto& self, const std::string& rid) -> int {
        if (!ids.count(rid)) {
            err_code = "NONCANONICAL_PAYLOAD";
            err = "unresolved dependency";
            return -1;
        }
        if (active.count(rid)) {
            err_code = "DEPENDENCY_CYCLE";
            err = "dependency cycle";
            return -1;
        }
        if (heights.count(rid)) return heights[rid];
        active.insert(rid);
        if (active.size() > 9) {
            err_code = "NONCANONICAL_PAYLOAD";
            err = "dependency depth exceeded";
            return -1;
        }
        const UniValue& rec = ids[rid];
        int h = 0;
        if (rec.exists("dependencies")) {
            const UniValue& deps = rec["dependencies"];
            if (!deps.isArray() || deps.size() > 256) {
                err_code = "NONCANONICAL_PAYLOAD";
                err = "dependency list";
                return -1;
            }
            for (const auto& child : deps.getValues()) {
                if (!child.isStr()) {
                    err_code = "NONCANONICAL_PAYLOAD";
                    err = "dependency list";
                    return -1;
                }
                const int ch = self(self, child.get_str());
                if (ch < 0) return -1;
                h = std::max(h, 1 + ch);
            }
        }
        if (h > 8) {
            err_code = "NONCANONICAL_PAYLOAD";
            err = "dependency depth exceeded";
            return -1;
        }
        active.erase(rid);
        heights[rid] = h;
        return h;
    };
    for (const auto& e : ids) {
        if (height(height, e.first) < 0) return false;
    }
    return true;
}

bool ValidateHandoff(const UniValue& ah, const std::map<std::string, UniValue>& ids, const UniValue& variants,
                     std::string& err_code, std::string& err)
{
    const std::set<std::string> req{"version", "entry_document", "client_requirements", "acquisition", "runtime_profiles"};
    const std::set<std::string> allow = [&] {
        auto s = req;
        s.insert("channel_ref");
        return s;
    }();
    if (!ExactKeys(ah, req, allow, "agent handoff", err_code, err)) return false;
    if (!ah["version"].isNum() || ah["version"].getValStr() != "1" || !ah["entry_document"].isStr() ||
        ah["entry_document"].get_str() != "AGENTS.md") {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "handoff version/entry");
    }
    const UniValue& cr = ah["client_requirements"];
    const std::set<std::string> cr_req{"distribution_id", "required_capabilities"};
    const std::set<std::string> cr_allow{"distribution_id", "required_capabilities", "minimum_client_version",
                                         "documentation_hints"};
    if (!ExactKeys(cr, cr_req, cr_allow, "client requirements", err_code, err)) return false;
    if (!cr["required_capabilities"].isArray()) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "client capabilities");
    }
    std::set<std::string> caps;
    for (const auto& c : cr["required_capabilities"].getValues()) {
        if (!c.isStr()) return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "client capabilities");
        caps.insert(c.get_str());
    }
    if (!caps.count(BTXPKG_CORE_V2) || !caps.count(AGENT_HANDOFF_V1)) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "client capabilities");
    }
    const UniValue& ac = ah["acquisition"];
    const std::set<std::string> ac_req{"retrieval_mode", "source_policy", "ready_requirement", "offer_seeding"};
    const std::set<std::string> ac_allow{"retrieval_mode", "source_policy", "ready_requirement", "offer_seeding",
                                         "default_variant"};
    if (!ExactKeys(ac, ac_req, ac_allow, "acquisition", err_code, err)) return false;
    if (!ac["retrieval_mode"].isStr() || ac["retrieval_mode"].get_str() != "FREE_ONLY") {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "no package auto-pay");
    }
    static const std::set<std::string> src_pol{"NATIVE_ONLY", "LOCAL_POLICY"};
    static const std::set<std::string> ready{"VERIFIED_LOCAL_FILES", "VERIFIED_SELECTION"};
    if (!InSet(ac["source_policy"], src_pol, "source policy", err_code, err)) return false;
    if (!InSet(ac["ready_requirement"], ready, "ready requirement", err_code, err)) return false;
    if (!ac["offer_seeding"].isBool()) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "offer_seeding boolean");
    }
    const UniValue& profiles = ah["runtime_profiles"];
    if (!profiles.isArray() || profiles.size() > 16) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "runtime profile count");
    }
    std::set<std::string> profile_ids;
    const std::set<std::string> pr_req{"profile_id", "adapter_id", "adapter_schema", "variant_ids", "mode", "parameters"};
    const std::set<std::string> pr_allow{"profile_id", "adapter_id", "adapter_schema", "variant_ids", "mode",
                                         "parameters", "minimum_version", "backend", "documentation_path"};
    static const std::set<std::string> modes{"CLI", "LOOPBACK_SERVICE"};
    static const std::set<std::string> param_keys{"context_tokens", "gpu_layers", "threads"};
    for (const auto& p : profiles.getValues()) {
        if (!ExactKeys(p, pr_req, pr_allow, "runtime profile", err_code, err)) return false;
        if (!SafeText(p["profile_id"], "profile id", err_code, err)) return false;
        if (!profile_ids.insert(p["profile_id"].get_str()).second) {
            return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "duplicate profile");
        }
        if (!InSet(p["mode"], modes, "remote runtime forbidden", err_code, err)) return false;
        if (!p["parameters"].isObject()) {
            return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "unknown runtime parameter; trusted adapter required");
        }
        for (const auto& k : p["parameters"].getKeys()) {
            if (!param_keys.count(k)) {
                return Fail(err_code, err, "NONCANONICAL_PAYLOAD",
                            "unknown runtime parameter; trusted adapter required");
            }
        }
    }
    if (!variants.isArray() || variants.size() > 64) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "variant count");
    }
    std::set<std::string> vids;
    const std::set<std::string> vr_req{"variant_id", "name", "resource_id", "format"};
    const std::set<std::string> vr_allow{"variant_id", "name", "resource_id", "format", "quantization",
                                         "dependencies", "runtime_profile_ids", "compatibility"};
    for (const auto& v : variants.getValues()) {
        if (!ExactKeys(v, vr_req, vr_allow, "variant", err_code, err)) return false;
        if (!SafeText(v["variant_id"], "variant id", err_code, err)) return false;
        if (!vids.insert(v["variant_id"].get_str()).second) {
            return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "duplicate variant");
        }
        if (!v["resource_id"].isStr() || !ids.count(v["resource_id"].get_str())) {
            return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "missing variant model");
        }
        const UniValue& rec = ids.at(v["resource_id"].get_str());
        if (!rec["kind"].isStr() || rec["kind"].get_str() != "MODEL") {
            return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "variant must name model");
        }
        if (v.exists("dependencies")) {
            if (!v["dependencies"].isArray()) {
                return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "variant missing dependency");
            }
            for (const auto& d : v["dependencies"].getValues()) {
                if (!d.isStr() || !ids.count(d.get_str())) {
                    return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "variant missing dependency");
                }
            }
        }
        if (v.exists("runtime_profile_ids")) {
            if (!v["runtime_profile_ids"].isArray()) {
                return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "missing runtime profile");
            }
            for (const auto& d : v["runtime_profile_ids"].getValues()) {
                if (!d.isStr() || !profile_ids.count(d.get_str())) {
                    return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "missing runtime profile");
                }
            }
        }
    }
    if (ac.exists("default_variant")) {
        if (!ac["default_variant"].isStr() || !vids.count(ac["default_variant"].get_str())) {
            return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "missing default variant");
        }
    }
    for (const auto& p : profiles.getValues()) {
        if (!p["variant_ids"].isArray()) {
            return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "profile names missing variant");
        }
        for (const auto& d : p["variant_ids"].getValues()) {
            if (!d.isStr() || !vids.count(d.get_str())) {
                return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "profile names missing variant");
            }
        }
    }
    return true;
}

bool ValidateLegacyCoreV1(const UniValue& core, std::string& err_code, std::string& err)
{
    if (!core.exists("network") || !InSet(core["network"], kNetworks, "network", err_code, err)) return false;
    if (!core.exists("package_type") || !InSet(core["package_type"], kPackageTypes, "package type", err_code, err)) {
        return false;
    }
    if (!core.exists("label") || !SafeText(core["label"], "label", err_code, err)) return false;
    if (core["label"].get_str().empty() || core["label"].get_str().size() > 256) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "label size");
    }
    if (!core.exists("resources")) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "legacy core missing fields");
    }
    std::map<std::string, UniValue> ids;
    if (!ValidateResources(core["resources"], ids, err_code, err)) return false;
    if (core.exists("documents") || core.exists("agent_handoff") || core.exists("capability_handoff") ||
        core.exists("capability_recipes") || core.exists("runtime_requirements") ||
        core.exists("verification_profiles")) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "v1 cannot contain handoff-v2/v3 fields");
    }
    return true;
}

bool CoreVersionNumber(const UniValue& core, int& ver, std::string& err)
{
    if (!core.isObject() || !core.exists("version") || !core["version"].isNum()) {
        err = "UNSUPPORTED_CORE_VERSION";
        return false;
    }
    const std::string& vs = core["version"].getValStr();
    if (vs == "1") {
        ver = 1;
        return true;
    }
    if (vs == "2") {
        ver = 2;
        return true;
    }
    if (vs == "3") {
        ver = 3;
        return true;
    }
    // Frame/codec versions are distinct from these package-core schema
    // versions. Core schema v1, v2, and v3 each have their own validator
    // (legacy / agent-handoff / capability-handoff); v4+ is rejected.
    err = "UNSUPPORTED_CORE_VERSION";
    return false;
}

} // namespace

bool PackageCoreId(const UniValue& core, Digest48& out, std::string& err)
{
    out = {};
    int ver = 0;
    if (!CoreVersionNumber(core, ver, err)) return false;
    std::vector<unsigned char> c;
    if (!EncodePjson1(core, c, err)) return false;
    const char* dom = PACKAGE_CORE_V1_DOMAIN;
    if (ver == 2) dom = PACKAGE_CORE_V2_DOMAIN;
    if (ver == 3) dom = PACKAGE_CORE_V3_DOMAIN;
    std::vector<unsigned char> pre;
    pre.insert(pre.end(), dom, dom + std::strlen(dom));
    pre.push_back(0x00);
    unsigned char lenle[8];
    WriteLE64(lenle, static_cast<uint64_t>(c.size()));
    pre.insert(pre.end(), lenle, lenle + 8);
    pre.insert(pre.end(), c.begin(), c.end());
    CSHA384 hasher;
    hasher.Write(pre.data(), pre.size());
    hasher.Finalize(out.data.data());
    return true;
}

bool EncodeBtxPackage(const UniValue& payload, std::vector<unsigned char>& out, std::string& err)
{
    out.clear();
    if (!payload.isObject()) {
        err = "package must be object";
        return false;
    }
    std::vector<unsigned char> body;
    if (!EncodePjson1(payload, body, err)) return false;
    if (body.size() > BTX_PACKAGE_MAX_PAYLOAD) {
        err = "PACKAGE_TOO_LARGE";
        return false;
    }
    CSHA384 hasher;
    hasher.Write(body.data(), body.size());
    unsigned char digest[48];
    hasher.Finalize(digest);
    out.resize(68 + body.size());
    std::memcpy(out.data(), BTXPKG_MAGIC, 8);
    WriteLE32(out.data() + 8, 0);
    WriteLE64(out.data() + 12, static_cast<uint64_t>(body.size()));
    std::memcpy(out.data() + 20, digest, 48);
    if (!body.empty()) {
        std::memcpy(out.data() + 68, body.data(), body.size());
    }
    return true;
}

bool DecodeBtxPackage(Span<const unsigned char> data, DecodedBtxPackage& out, std::string& err)
{
    out = {};
    if (data.size() < 68) {
        SetErr(out, "BAD_PACKAGE_MAGIC", "truncated header", err);
        return false;
    }
    if (std::memcmp(data.data(), BTXPKG_MAGIC, 8) != 0) {
        SetErr(out, "BAD_PACKAGE_MAGIC", "bad magic", err);
        return false;
    }
    out.flags = ReadLE32(data.data() + 8);
    out.payload_len = ReadLE64(data.data() + 12);
    if (out.flags != 0) {
        SetErr(out, "BAD_PACKAGE_MAGIC", "flags", err);
        return false;
    }
    // Reject 2^64-1 and any oversize length before 68+n arithmetic or payload alloc.
    if (out.payload_len == std::numeric_limits<uint64_t>::max() ||
        out.payload_len > BTX_PACKAGE_MAX_PAYLOAD) {
        SetErr(out, "PACKAGE_TOO_LARGE", "PACKAGE_TOO_LARGE", err);
        return false;
    }
    if (static_cast<uint64_t>(data.size() - 68) != out.payload_len) {
        SetErr(out, "BAD_PACKAGE_MAGIC", "truncation or trailing bytes", err);
        return false;
    }
    CSHA384 hasher;
    hasher.Write(data.data() + 68, static_cast<size_t>(out.payload_len));
    unsigned char digest[48];
    hasher.Finalize(digest);
    std::memcpy(out.frame_sha384.data.data(), digest, 48);
    if (std::memcmp(digest, data.data() + 20, 48) != 0) {
        SetErr(out, "NONCANONICAL_PAYLOAD", "payload digest mismatch", err);
        return false;
    }
    if (!DecodePjson1(Span<const unsigned char>{data.data() + 68, static_cast<size_t>(out.payload_len)}, out.payload,
                      err)) {
        out.err_code = "NONCANONICAL_PAYLOAD";
        if (err.empty()) err = "NONCANONICAL_PAYLOAD";
        return false;
    }
    if (!out.payload.isObject() || !out.payload.exists("core") || !out.payload["core"].isObject()) {
        SetErr(out, "NONCANONICAL_PAYLOAD", "core object", err);
        return false;
    }
    out.core = out.payload["core"];
    if (!CoreVersionNumber(out.core, out.core_version, err)) {
        SetErr(out, "UNSUPPORTED_CORE_VERSION", "UNSUPPORTED_CORE_VERSION", err);
        return false;
    }
    if (!PackageCoreId(out.core, out.package_core_id, err)) {
        SetErr(out, "UNSUPPORTED_CORE_VERSION", err, err);
        return false;
    }
    return true;
}

bool ValidateAgentPackageCore(const UniValue& core, std::string& err_code, std::string& err)
{
    err_code.clear();
    err.clear();
    if (!core.isObject()) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "core object");
    }
    int ver = 0;
    if (!CoreVersionNumber(core, ver, err) || ver != 2) {
        return Fail(err_code, err, "UNSUPPORTED_CORE_VERSION", "core must be v2");
    }
    if (!ExactKeys(core, kCoreV2Required, kCoreV2Allowed, "core", err_code, err)) return false;
    if (!InSet(core["network"], kNetworks, "network", err_code, err)) return false;
    if (!InSet(core["package_type"], kPackageTypes, "package type", err_code, err)) return false;
    if (!SafeText(core["label"], "label", err_code, err)) return false;
    if (core["label"].get_str().size() < 1 || core["label"].get_str().size() > 256) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "label size");
    }
    const UniValue& ex = core["critical_extensions"];
    if (!ex.isArray() || ex.size() < 1 || ex.size() > 8) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "critical extension list");
    }
    std::set<std::string> seen_ext;
    bool has_handoff = false;
    for (const auto& e : ex.getValues()) {
        if (!e.isStr()) {
            return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "critical extension list");
        }
        const std::string& name = e.get_str();
        if (!seen_ext.insert(name).second) {
            return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "critical feature declaration");
        }
        if (name == AGENT_HANDOFF_V1) has_handoff = true;
        if (!kCritical.count(name)) {
            return Fail(err_code, err, "UNSUPPORTED_CRITICAL_EXTENSION", name);
        }
    }
    if (!has_handoff) {
        return Fail(err_code, err, "UNSUPPORTED_CRITICAL_EXTENSION", AGENT_HANDOFF_V1);
    }
    if (!ValidatePackageDocuments(core["documents"], err_code, err)) return false;
    std::map<std::string, UniValue> ids;
    if (!ValidateResources(core["resources"], ids, err_code, err)) return false;
    UniValue econ = core.exists("economy_refs") ? core["economy_refs"] : UniValue(UniValue::VARR);
    if (!econ.isArray() || econ.size() > 64) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "economy count");
    }
    const std::set<std::string> econ_req{"kind", "id"};
    const std::set<std::string> econ_allow{"kind", "id", "terms_id", "label"};
    static const std::set<std::string> econ_kinds{"RELEASE", "BOUNTY"};
    for (const auto& r : econ.getValues()) {
        if (!ExactKeys(r, econ_req, econ_allow, "economy reference", err_code, err)) return false;
        if (!InSet(r["kind"], econ_kinds, "economy kind", err_code, err)) return false;
        if (!ValidDigestField(r["id"], err_code, err)) return false;
        if (r.exists("terms_id") && !ValidDigestField(r["terms_id"], err_code, err)) return false;
    }
    const std::string ptype = core["package_type"].get_str();
    if (ptype == "BOUNTY") {
        bool found = false;
        for (const auto& r : econ.getValues()) {
            if (r["kind"].get_str() == "BOUNTY") found = true;
        }
        if (!found) return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "bounty reference required");
    } else if (ids.empty()) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "resource required");
    }
    if (ptype == "RELEASE") {
        bool found = false;
        for (const auto& r : econ.getValues()) {
            if (r["kind"].get_str() == "RELEASE") found = true;
        }
        if (!found) return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "release reference required");
    }
    UniValue variants = core.exists("variants") ? core["variants"] : UniValue(UniValue::VARR);
    if (!ValidateHandoff(core["agent_handoff"], ids, variants, err_code, err)) return false;
    return true;
}

bool ValidateAgentHandoff(const UniValue& core, std::string& err_code, std::string& err)
{
    return ValidateAgentPackageCore(core, err_code, err);
}

bool ValidatePackagePayload(const UniValue& payload, std::string& err_code, std::string& err)
{
    if (!ExactKeys(payload, kPayloadRequired, kPayloadRequired, "payload", err_code, err)) return false;
    int ver = 0;
    if (!payload["core"].isObject() || !CoreVersionNumber(payload["core"], ver, err)) {
        return Fail(err_code, err, "UNSUPPORTED_CORE_VERSION", "core object");
    }
    if (!payload["observations"].isArray() || payload["observations"].size() > 256) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "observation count");
    }
    if (!payload["signatures"].isArray() || payload["signatures"].size() > 16) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "signature count");
    }
    if (ver == 1) return ValidateLegacyCoreV1(payload["core"], err_code, err);
    if (ver == 3) return ValidateCapabilityPackageCore(payload["core"], err_code, err);
    return ValidateAgentPackageCore(payload["core"], err_code, err);
}

bool VerifyPackageCoreSignature(const Digest48& core_id, const UniValue& signature, std::string& err_code,
                                std::string& err)
{
    if (!signature.isObject()) {
        return Fail(err_code, err, "SIGNATURE_INVALID", "signature object");
    }
    for (const char* k : {"scope", "algorithm", "signer_id", "public_key_hex", "signature_hex"}) {
        if (!signature.exists(k) || !signature[k].isStr()) {
            return Fail(err_code, err, "SIGNATURE_INVALID", k);
        }
    }
    if (signature["scope"].get_str() != "PACKAGE_CORE" || signature["algorithm"].get_str() != "ML-DSA-44") {
        return Fail(err_code, err, "SIGNATURE_INVALID", "scope/algorithm");
    }
    const auto pk = TryParseHex<unsigned char>(signature["public_key_hex"].get_str());
    const auto sig = TryParseHex<unsigned char>(signature["signature_hex"].get_str());
    if (!pk || pk->size() != MLDSA44_PK || !sig || sig->size() != MLDSA44_SIG) {
        return Fail(err_code, err, "SIGNATURE_INVALID", "signature shape");
    }
    if (PublisherId(Span<const unsigned char>{pk->data(), pk->size()}).Hex() != signature["signer_id"].get_str()) {
        return Fail(err_code, err, "SIGNER_IDENTITY_MISMATCH", "signer_id");
    }
    if (!VerifyMlDsa44(Span<const unsigned char>{pk->data(), pk->size()},
                         Span<const unsigned char>{core_id.data.data(), core_id.data.size()},
                         Span<const unsigned char>{sig->data(), sig->size()})) {
        return Fail(err_code, err, "SIGNATURE_INVALID", "ML-DSA verify");
    }
    return true;
}

bool ParseAgentPackageFile(Span<const unsigned char> data, DecodedBtxPackage& out, std::string& err)
{
    // Framing + core schema only. An empty signatures array is valid so
    // inspect fixtures can be decoded; install/verify paths must still
    // require a cryptographic PASS (see importbtxpackage / verifybtxpackage).
    if (!DecodeBtxPackage(data, out, err)) return false;
    std::string code;
    if (!ExactKeys(out.payload, kPayloadRequired, kPayloadRequired, "payload", code, err)) {
        out.err_code = code;
        return false;
    }
    if (!out.payload["observations"].isArray() || out.payload["observations"].size() > 256) {
        SetErr(out, "NONCANONICAL_PAYLOAD", "observation count", err);
        return false;
    }
    if (!out.payload["signatures"].isArray() || out.payload["signatures"].size() > 16) {
        SetErr(out, "NONCANONICAL_PAYLOAD", "signature count", err);
        return false;
    }
    if (out.core_version == 1) {
        if (!ValidateLegacyCoreV1(out.core, code, err)) {
            out.err_code = code;
            return false;
        }
        return true;
    }
    if (out.core_version == 3) {
        if (!ValidateCapabilityPackageCore(out.core, code, err)) {
            out.err_code = code;
            return false;
        }
        return true;
    }
    if (!ValidateAgentPackageCore(out.core, code, err)) {
        out.err_code = code;
        return false;
    }
    return true;
}

} // namespace modelnet
