// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/capability.h>

#include <modelnet/package_core.h>
#include <modelnet/package_documents.h>
#include <modelnet/package_pjson.h>
#include <crypto/sha384.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstdlib>
#include <functional>
#include <map>
#include <set>

namespace modelnet {
namespace {

bool Fail(std::string& err_code, std::string& err, const char* code, const std::string& msg)
{
    err_code = code;
    err = msg.empty() ? code : msg;
    return false;
}

bool Hex96(const UniValue& v)
{
    return v.isStr() && v.get_str().size() == 96 && IsHex(v.get_str());
}

std::string LowerKey(std::string s)
{
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

bool ForbiddenAuthorityKey(const std::string& k)
{
    const std::string low = LowerKey(k);
    return low == "skip_verification" || low == "disable_verification" || low == "skip_hash" ||
           low == "skip_hash_checks" || low == "software_trust_root" || low == "trust_root" ||
           low == "trusted_builder" || low == "publisher_as_builder" ||
           low == "publisher_authorizes_executable" || low == "executable_path" || low == "ld_preload" ||
           low == "author_is_trust_root" || low == "package_author_trust" ||
           low == "accept_publisher_cache" || low == "executable_cache_ok" ||
           low == "installer_key" || low == "installer_url" || low == "installer_sha384";
}

bool AtomsExactlyZero(const UniValue& v)
{
    if (v.isNum()) {
        const std::string tok = v.getValStr();
        return tok == "0" || tok == "-0";
    }
    if (v.isStr()) return v.get_str() == "0";
    return false;
}

bool RejectAuthorityAndPaid(const UniValue& o, std::string& err_code, std::string& err)
{
    if (o.isObject()) {
        std::set<std::string> seen;
        const auto& keys = o.getKeys();
        const auto& vals = o.getValues();
        if (keys.size() != vals.size()) {
            return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "object");
        }
        for (size_t i = 0; i < keys.size(); ++i) {
            if (!seen.insert(keys[i]).second) {
                return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "duplicate key");
            }
            if (ForbiddenAuthorityKey(keys[i])) {
                return Fail(err_code, err, "SOFTWARE_TRUST_REQUIRED",
                            keys[i] + " is not package or publisher authority");
            }
            if (keys[i] == "automatic_spend_atoms" && !AtomsExactlyZero(vals[i])) {
                return Fail(err_code, err, "PAID_PATH_FORBIDDEN", "automatic_spend_atoms must remain 0");
            }
            if (!RejectAuthorityAndPaid(vals[i], err_code, err)) return false;
        }
    } else if (o.isArray()) {
        for (const auto& e : o.getValues()) {
            if (!RejectAuthorityAndPaid(e, err_code, err)) return false;
        }
    }
    return true;
}

} // namespace

bool RecipeDigest(const UniValue& recipe_body, Digest48& out, std::string& err)
{
    return CapabilityObjectIdJson(RECIPE_DOMAIN, recipe_body, out, err);
}

bool ParseCapabilityRecipe(const UniValue& o, CapabilityRecipe& out, std::string& err_code, std::string& err)
{
    out = {};
    if (!o.isObject()) return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "recipe object");
    if (o.exists("natural_language")) {
        return Fail(err_code, err, "TYPED_PLAN_REQUIRED", "natural language cannot execute");
    }
    if (!RejectAuthorityAndPaid(o, err_code, err)) return false;
    if (!o.exists("recipe_kind") || !o["recipe_kind"].isStr() || !RecipeKindFromName(o["recipe_kind"].get_str(), out.kind)) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "recipe_kind");
    }
    if (!o.exists("components") || !o["components"].isArray()) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "components");
    }
    if (o["components"].size() > CAPABILITY_RESOURCE_MAX) {
        return Fail(err_code, err, "RESOURCE_LIMIT", "256 resources");
    }
    if (o.exists("capabilities") && o["capabilities"].isArray()) {
        for (const auto& c : o["capabilities"].getValues()) {
            if (!c.isStr()) return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "capability label");
            out.capabilities.push_back(c.get_str());
        }
    }
    std::set<std::string> names;
    for (const auto& c : o["components"].getValues()) {
        if (!c.isObject() || !c.exists("name") || !c["name"].isStr()) {
            return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "component name");
        }
        if (!names.insert(c["name"].get_str()).second) {
            return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "duplicate component");
        }
        if (!c.exists("resource") || !c["resource"].isObject() || !c["resource"].exists("digest48") ||
            !Hex96(c["resource"]["digest48"])) {
            return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "component digest");
        }
        out.component_ids.push_back(c["resource"]["digest48"].get_str());
        if (c.exists("role") && c["role"].isStr() && c["role"].get_str() == "ADAPTER") {
            if (!c.exists("base_binding") || !c["base_binding"].isStr() || c["base_binding"].get_str().empty()) {
                return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "adapter base_binding");
            }
        }
    }
    if (o.exists("readiness_contract") && o["readiness_contract"].isStr()) {
        const std::string rc = o["readiness_contract"].get_str();
        if (rc == "VERIFIED_DEMAND_PAGING") out.readiness = ReadinessContract::VERIFIED_DEMAND_PAGING;
        else if (rc == "PARTITIONED_VALIDATED") out.readiness = ReadinessContract::PARTITIONED_VALIDATED;
        else if (rc != "FULL_REQUIRED_SET") return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "readiness_contract");
    }
    out.json = o;
    if (!RecipeGraphOk(out, err_code, err)) return false;
    if (!RecipeDigest(o, out.recipe_id, err)) return Fail(err_code, err, "NONCANONICAL_PAYLOAD", err);
    if (o.exists("recipe_id") && o["recipe_id"].isStr() && o["recipe_id"].get_str() != out.recipe_id.Hex()) {
        return Fail(err_code, err, "ID_MISMATCH", "recipe_id");
    }
    return true;
}

bool RecipeGraphOk(const CapabilityRecipe& r, std::string& err_code, std::string& err)
{
    if (r.component_ids.size() > CAPABILITY_RESOURCE_MAX) {
        return Fail(err_code, err, "RESOURCE_LIMIT", "256 resources");
    }
    std::map<std::string, std::string> base_of;
    if (!r.json.exists("components") || !r.json["components"].isArray()) return true;
    for (const auto& c : r.json["components"].getValues()) {
        if (!c.isObject()) continue;
        const std::string name = c["name"].get_str();
        if (c.exists("depends_on") && c["depends_on"].isArray()) {
            if (static_cast<int>(c["depends_on"].size()) > CAPABILITY_DEPTH_MAX) {
                return Fail(err_code, err, "RESOURCE_LIMIT", "depth 16");
            }
            for (const auto& d : c["depends_on"].getValues()) {
                if (!d.isStr()) return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "depends_on");
                if (d.get_str() == name) return Fail(err_code, err, "CYCLE", name);
            }
        }
        if (c.exists("base_binding") && c["base_binding"].isStr() && !c["base_binding"].isNull()) {
            base_of[name] = c["base_binding"].get_str();
        }
    }
    std::set<std::string> visiting, done;
    std::function<bool(const std::string&)> dfs = [&](const std::string& n) -> bool {
        if (done.count(n)) return true;
        if (visiting.count(n)) return false;
        visiting.insert(n);
        for (const auto& c : r.json["components"].getValues()) {
            if (!c.isObject() || c["name"].get_str() != n) continue;
            if (c.exists("depends_on") && c["depends_on"].isArray()) {
                for (const auto& d : c["depends_on"].getValues()) {
                    if (d.isStr() && !dfs(d.get_str())) return false;
                }
            }
        }
        visiting.erase(n);
        done.insert(n);
        return true;
    };
    for (const auto& c : r.json["components"].getValues()) {
        if (c.isObject() && !dfs(c["name"].get_str())) {
            return Fail(err_code, err, "CYCLE", "dependency cycle");
        }
    }
    std::set<std::string> tokenizers;
    for (const auto& c : r.json["components"].getValues()) {
        if (!c.isObject()) continue;
        const std::string role = c.exists("role") && c["role"].isStr() ? c["role"].get_str() : "";
        if (role == "TOKENIZER" || (c.exists("kind") && c["kind"].isStr() && c["kind"].get_str() == "TOKENIZER")) {
            const std::string id = c.exists("resource") && c["resource"].isObject() && c["resource"].exists("digest48") ?
                                      c["resource"]["digest48"].get_str() :
                                      c.exists("name") ? c["name"].get_str() : "";
            tokenizers.insert(id);
        }
    }
    if (tokenizers.size() > 1) {
        return Fail(err_code, err, "TOKENIZER_CONFLICT", "incompatible tokenizer/vocabulary");
    }
    return true;
}

bool ParseCapabilityLock(const UniValue& o, CapabilityLock& out, std::string& err_code, std::string& err)
{
    out = {};
    if (!o.isObject()) return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "lock object");
    if (!RejectAuthorityAndPaid(o, err_code, err)) return false;
    if (o.exists("latest") && o["latest"].isTrue()) {
        return Fail(err_code, err, "LOCKED_REPRODUCIBILITY", "latest forbidden in lock");
    }
    if (o.exists("recipe_id") && !Hex96(o["recipe_id"])) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "recipe_id");
    }
    out.json = o;
    if (!CapabilityObjectIdJson(LOCK_DOMAIN, o, out.lock_id, err)) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", err);
    }
    if (o.exists("recipe_id") && o["recipe_id"].isStr()) {
        (void)Digest48::FromHex(o["recipe_id"].get_str(), out.recipe_id, err);
    }
    if (o.exists("package_core_id") && o["package_core_id"].isStr()) {
        (void)Digest48::FromHex(o["package_core_id"].get_str(), out.package_core_id, err);
    }
    return true;
}

bool EnsureLockedPins(const CapabilityLock& lock, const CapabilityRecipe& recipe, std::string& err_code, std::string& err)
{
    if (!lock.recipe_id.IsNull() && lock.recipe_id != recipe.recipe_id) {
        return Fail(err_code, err, "LOCKED_REPRODUCIBILITY", "recipe pin");
    }
    return true;
}

bool ExportLockBytes(const CapabilityLock& lock, std::vector<unsigned char>& out, std::string& err)
{
    return EncodePjson1(lock.json, out, err);
}

bool ParseGrant(const UniValue& o, LocalCapabilityGrant& out, std::string& err_code, std::string& err)
{
    out = {};
    if (!o.isObject()) return Fail(err_code, err, "INVALID_PARAMETER", "grant object");
    if (!RejectAuthorityAndPaid(o, err_code, err)) return false;
    out.json = o;
    out.grant_id = o.exists("grant_id") && o["grant_id"].isStr() ? o["grant_id"].get_str() : GenerationHex(NewGeneration());
    out.caller = o.exists("caller") && o["caller"].isStr() ? o["caller"].get_str() : "local";
    if (o.exists("expires_at_ms")) {
        if (o["expires_at_ms"].isNum()) out.expires_at_ms = o["expires_at_ms"].getInt<int64_t>();
        else if (o["expires_at_ms"].isStr()) out.expires_at_ms = std::strtoll(o["expires_at_ms"].get_str().c_str(), nullptr, 10);
    }
    out.revoked = o.exists("revoked") && o["revoked"].isTrue();
    if (o.exists("host_bytes")) {
        if (o["host_bytes"].isNum()) out.host_bytes = o["host_bytes"].getInt<uint64_t>();
        else if (o["host_bytes"].isStr()) out.host_bytes = std::strtoull(o["host_bytes"].get_str().c_str(), nullptr, 10);
    }
    if (o.exists("device_bytes") && o["device_bytes"].isNum()) {
        out.device_bytes = o["device_bytes"].getInt<uint64_t>();
    }
    if (o.exists("max_sessions") && o["max_sessions"].isNum()) out.max_sessions = o["max_sessions"].getInt<int>();
    if (out.max_sessions < 1) out.max_sessions = 1;
    out.json.pushKV("automatic_spend_atoms", 0);
    return true;
}

bool GrantAllows(const LocalCapabilityGrant& g, const std::string& effect, int64_t now_ms, std::string& err_code,
                 std::string& err)
{
    if (g.revoked) return Fail(err_code, err, "GRANT_REVOKED", "revoked");
    if (g.expires_at_ms > 0 && now_ms > g.expires_at_ms) return Fail(err_code, err, "GRANT_EXPIRED", "expired");
    if (effect.find("wallet") != std::string::npos || effect.find("spend") != std::string::npos) {
        return Fail(err_code, err, "PAID_PATH_FORBIDDEN", "grant cannot spend");
    }
    if (effect == "INSTALL_PRIVILEGED" || effect == "RDMA_PUBLIC" || effect == "REMOTE_INFERENCE") {
        return Fail(err_code, err, "EFFECT_DENIED", effect);
    }
    return true;
}

bool ParseMemoryLimits(const UniValue& o, MemoryLimits& out, std::string& err_code, std::string& err)
{
    out = {};
    if (!o.isObject()) return Fail(err_code, err, "INVALID_PARAMETER", "memory limits");
    auto u64 = [&](const char* k, uint64_t& dst) {
        if (!o.exists(k)) return true;
        if (o[k].isNum()) {
            dst = o[k].getInt<uint64_t>();
            return true;
        }
        if (o[k].isStr()) {
            dst = std::strtoull(o[k].get_str().c_str(), nullptr, 10);
            return true;
        }
        return false;
    };
    if (!u64("host_physical_bytes", out.host_physical_bytes)) return Fail(err_code, err, "INVALID_PARAMETER", "host");
    if (!u64("host_pinned_bytes", out.host_pinned_bytes)) return Fail(err_code, err, "INVALID_PARAMETER", "pinned");
    if (!u64("device_bytes", out.device_bytes) && o.exists("device_bytes") && o["device_bytes"].isObject()) {
        uint64_t sum = 0;
        for (const auto& k : o["device_bytes"].getKeys()) {
            const UniValue& v = o["device_bytes"][k];
            if (v.isNum()) sum += v.getInt<uint64_t>();
            else if (v.isStr()) sum += std::strtoull(v.get_str().c_str(), nullptr, 10);
        }
        out.device_bytes = sum;
    }
    if (!u64("speculative_bytes", out.speculative_bytes)) return Fail(err_code, err, "INVALID_PARAMETER", "speculative");
    out.uma = o.exists("uma") && o["uma"].isTrue();
    if (out.host_pinned_bytes > out.host_physical_bytes && out.host_physical_bytes != 0) {
        return Fail(err_code, err, "BUDGET_EXCEEDED", "pinned exceeds host");
    }
    return true;
}

bool RejectLegacyModelHandshake(int peer_core_version, std::string& err_code, std::string& err)
{
    if (peer_core_version < 3) {
        return Fail(err_code, err, "UNSUPPORTED_CORE_VERSION", "0.34.7 model handshake rejected after Core v3 cutover");
    }
    return true;
}

bool MigratePriorPackageState(const UniValue& old_meta, UniValue& new_meta, std::string& err_code, std::string& err)
{
    new_meta = UniValue(UniValue::VOBJ);
    new_meta.pushKV("schema_version", 3);
    new_meta.pushKV("migrated", true);
    new_meta.pushKV("automatic_spend_atoms", 0);
    if (old_meta.isObject() && old_meta.exists("verified_representation") && old_meta["verified_representation"].isStr()) {
        new_meta.pushKV("verified_representation", old_meta["verified_representation"]);
    }
    if (old_meta.isObject() && old_meta.exists("phase") && old_meta["phase"].isStr()) {
        const std::string p = old_meta["phase"].get_str();
        if (p == "crash-mid-journal") {
            new_meta.pushKV("resumed", true);
            new_meta.pushKV("rolled_back", false);
        }
    }
    (void)err_code;
    (void)err;
    return true;
}

bool ValidateCapabilityPackageCore(const UniValue& core, std::string& err_code, std::string& err)
{
    err_code.clear();
    err.clear();
    if (!core.isObject()) return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "core object");
    if (!RejectAuthorityAndPaid(core, err_code, err)) return false;
    if (!core.exists("version") || !core["version"].isNum() || core["version"].getValStr() != "3") {
        return Fail(err_code, err, "UNSUPPORTED_CORE_VERSION", "core must be v3");
    }
    static const char* required[] = {"version", "network", "package_type", "label", "resources", "critical_extensions",
                                        "documents", "capability_handoff", "capability_recipes", "runtime_requirements",
                                        "verification_profiles"};
    for (const char* k : required) {
        if (!core.exists(k)) return Fail(err_code, err, "NONCANONICAL_PAYLOAD", k);
    }
    static const std::set<std::string> allowed{
        "version",         "network",
        "package_type",    "label",
        "resources",       "critical_extensions",
        "documents",       "capability_handoff",
        "capability_recipes", "runtime_requirements",
        "verification_profiles", "prefetch_hints",
        "agent_handoff",   "variants",
        "economy_refs",    "source_hints"};
    for (const auto& k : core.getKeys()) {
        if (!allowed.count(k)) return Fail(err_code, err, "NONCANONICAL_PAYLOAD", std::string("unknown field ") + k);
    }
    if (!core["network"].isStr()) return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "network");
    const std::string net = core["network"].get_str();
    if (net != "MAINNET" && net != "TESTNET" && net != "REGTEST") {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "network");
    }
    if (!core["critical_extensions"].isArray()) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "critical_extensions");
    }
    bool has_cap = false;
    for (const auto& e : core["critical_extensions"].getValues()) {
        if (!e.isStr()) return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "critical extension");
        const std::string n = e.get_str();
        if (n == CAPABILITY_HANDOFF_V1) has_cap = true;
        else if (n != AGENT_HANDOFF_V1) {
            return Fail(err_code, err, "UNSUPPORTED_CRITICAL_EXTENSION", n);
        }
    }
    if (!has_cap) return Fail(err_code, err, "UNSUPPORTED_CRITICAL_EXTENSION", CAPABILITY_HANDOFF_V1);
    if (!ValidatePackageDocuments(core["documents"], err_code, err)) return false;
    if (!core["resources"].isArray() || core["resources"].empty()) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "resource required");
    }
    for (const auto& r : core["resources"].getValues()) {
        if (!r.isObject() || !r.exists("kind") || !r.exists("id") || !r["id"].isStr()) {
            return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "resource");
        }
        Digest48 rid;
        std::string hexerr;
        if (!Digest48::FromHex(r["id"].get_str(), rid, hexerr)) {
            return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "resource");
        }
    }
    const UniValue& ch = core["capability_handoff"];
    if (!ch.isObject() || !ch.exists("client_requirements") || !ch["client_requirements"].isObject()) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "capability_handoff");
    }
    const UniValue& cr = ch["client_requirements"];
    if (!cr.exists("required_capabilities") || !cr["required_capabilities"].isArray()) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "client capabilities");
    }
    bool has_v3 = false, has_h = false;
    for (const auto& c : cr["required_capabilities"].getValues()) {
        if (!c.isStr()) return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "client capabilities");
        if (c.get_str() == BTXPKG_CORE_V3) has_v3 = true;
        if (c.get_str() == CAPABILITY_HANDOFF_V1) has_h = true;
    }
    if (!has_v3 || !has_h) return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "client capabilities");
    if (ch.exists("acquisition") && ch["acquisition"].isObject()) {
        const UniValue& ac = ch["acquisition"];
        if (ac.exists("retrieval_mode") && ac["retrieval_mode"].isStr() && ac["retrieval_mode"].get_str() != "FREE_ONLY") {
            return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "no package auto-pay");
        }
        if (ac.exists("source_policy") && ac["source_policy"].isStr() &&
            ac["source_policy"].get_str() != "NATIVE_ONLY" && ac["source_policy"].get_str() != "LOCAL_POLICY") {
            return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "source policy");
        }
    }
    if (ch.exists("runtime_profiles") && ch["runtime_profiles"].isArray()) {
        for (const auto& p : ch["runtime_profiles"].getValues()) {
            if (!p.isObject()) continue;
            if (p.exists("mode") && p["mode"].isStr()) {
                const std::string m = p["mode"].get_str();
                if (m != "CLI" && m != "LOOPBACK_SERVICE") {
                    return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "remote runtime forbidden");
                }
            }
            if (p.exists("parameters") && p["parameters"].isObject()) {
                static const std::set<std::string> pk{"context_tokens", "gpu_layers", "threads"};
                for (const auto& k : p["parameters"].getKeys()) {
                    if (!pk.count(k)) {
                        return Fail(err_code, err, "NONCANONICAL_PAYLOAD",
                                    "unknown runtime parameter; trusted adapter required");
                    }
                }
            }
        }
    }
    if (!core["capability_recipes"].isArray() || core["capability_recipes"].size() > CAPABILITY_CANDIDATE_MAX) {
        return Fail(err_code, err, "RESOURCE_LIMIT", "recipes");
    }
    for (const auto& rec : core["capability_recipes"].getValues()) {
        if (!rec.isObject()) return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "recipe");
        if (rec.exists("recipe_kind") || rec.exists("components")) {
            CapabilityRecipe parsed;
            if (!ParseCapabilityRecipe(rec, parsed, err_code, err)) return false;
        }
    }
    if (!core["runtime_requirements"].isArray() || !core["verification_profiles"].isArray()) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "runtime/verification arrays");
    }
    if (core.exists("prefetch_hints") && !core["prefetch_hints"].isArray()) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "prefetch_hints");
    }
    return true;
}

} // namespace modelnet
