// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/package_acquisition.h>

#include <crypto/common.h>
#include <crypto/sha384.h>
#include <modelnet/package_core.h>
#include <modelnet/package_pjson.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {
namespace {

constexpr int kMaxDepDepth = 8;
constexpr size_t kMaxDepNodes = 256;
constexpr size_t kMaxResources = 256;
constexpr size_t kMaxVariants = 64;
constexpr const char* ACQUISITION_PLAN_DOMAIN = "BTX/AcquisitionPlan/v1";

bool Fail(std::string& err_code, std::string& err, const char* code, const std::string& msg)
{
    err_code = code;
    err = msg.empty() ? code : msg;
    return false;
}

const UniValue& CoreObj(const UniValue& in)
{
    if (in.isObject() && !in.exists("version") && in.exists("core") && in["core"].isObject()) {
        return in["core"];
    }
    return in;
}

std::string AsStr(const UniValue& v)
{
    if (v.isStr()) return v.get_str();
    if (v.isNum()) return v.getValStr();
    return {};
}

bool FieldStr(const UniValue& obj, const char* key, std::string& out)
{
    if (!obj.isObject() || !obj.exists(key)) return false;
    out = AsStr(obj[key]);
    return !out.empty();
}

std::vector<std::string> AsStrings(const UniValue& v)
{
    std::vector<std::string> out;
    if (v.isStr()) {
        if (!v.get_str().empty()) out.push_back(v.get_str());
        return out;
    }
    if (!v.isArray()) return out;
    for (const auto& e : v.getValues()) {
        if (e.isStr() && !e.get_str().empty()) out.push_back(e.get_str());
    }
    return out;
}

/** Missing observation key is unconstrained. An empty present list is a real constraint. */
void ObsList(const UniValue& obs, const char* plural, const char* singular, std::vector<std::string>& out, bool& present)
{
    out.clear();
    present = false;
    if (!obs.isObject()) return;
    if (obs.exists(plural)) {
        present = true;
        out = AsStrings(obs[plural]);
        return;
    }
    if (singular && obs.exists(singular)) {
        present = true;
        out = AsStrings(obs[singular]);
    }
}

bool IntersectsOrUnconstrained(const std::vector<std::string>& need, const std::vector<std::string>& have, bool have_present)
{
    if (need.empty() || !have_present) return true;
    for (const auto& n : need) {
        if (std::find(have.begin(), have.end(), n) != have.end()) return true;
    }
    return false;
}

bool ParseU64Field(const UniValue& obj, const char* key, uint64_t& out, bool& present)
{
    present = false;
    out = 0;
    if (!obj.isObject() || !obj.exists(key)) return true;
    const std::string s = AsStr(obj[key]);
    if (s.empty()) return true;
    present = true;
    return ParseUInt64(s, &out);
}

UniValue OmitKeys(const UniValue& obj, const std::set<std::string>& skip)
{
    UniValue out(UniValue::VOBJ);
    if (!obj.isObject()) return out;
    for (const auto& k : obj.getKeys()) {
        if (skip.count(k)) continue;
        out.pushKV(k, obj[k]);
    }
    return out;
}

bool DomainPlanDigest(const char* domain, const UniValue& body, Digest48& out, std::string& err)
{
    out = {};
    std::vector<unsigned char> canon;
    if (!EncodePjson1(body, canon, err)) return false;
    std::vector<unsigned char> pre;
    pre.insert(pre.end(), domain, domain + std::strlen(domain));
    pre.push_back(0);
    unsigned char lenle[8];
    WriteLE64(lenle, static_cast<uint64_t>(canon.size()));
    pre.insert(pre.end(), lenle, lenle + 8);
    pre.insert(pre.end(), canon.begin(), canon.end());
    CSHA384 hasher;
    hasher.Write(pre.data(), pre.size());
    hasher.Finalize(out.data.data());
    return true;
}

struct ResourceRec {
    const UniValue* obj{nullptr};
    std::string id;
    std::string kind;
    std::vector<std::string> deps;
    uint64_t size_bytes{0};
    bool size_known{false};
};

struct VariantRec {
    const UniValue* obj{nullptr};
    std::string variant_id;
    std::string resource_id;
    std::string format;
    std::vector<std::string> deps;
    std::vector<std::string> runtime_profile_ids;
    std::vector<std::string> architectures;
    std::vector<std::string> operating_systems;
    std::vector<std::string> backends;
    uint64_t min_ram{0};
    uint64_t min_vram{0};
    uint64_t weight_bytes{0};
    uint64_t kv_overhead_bytes{0};
    uint64_t runtime_overhead_bytes{0};
    bool min_ram_known{false};
    bool min_vram_known{false};
    bool weight_known{false};
    bool kv_known{false};
    bool runtime_known{false};
};

bool IndexResources(const UniValue& core, std::map<std::string, ResourceRec>& by_id, std::string& err_code, std::string& err)
{
    by_id.clear();
    if (!core.exists("resources")) return true;
    if (!core["resources"].isArray()) {
        return Fail(err_code, err, "MISSING_RESOURCE", "resources must be an array");
    }
    const auto& arr = core["resources"].getValues();
    if (arr.size() > kMaxResources) {
        return Fail(err_code, err, "MISSING_RESOURCE", "resource count");
    }
    for (const auto& r : arr) {
        if (!r.isObject() || !r.exists("id") || !r["id"].isStr()) {
            return Fail(err_code, err, "MISSING_RESOURCE", "resource id");
        }
        ResourceRec rec;
        rec.obj = &r;
        rec.id = r["id"].get_str();
        rec.kind = r.exists("kind") && r["kind"].isStr() ? r["kind"].get_str() : std::string{};
        if (r.exists("dependencies")) rec.deps = AsStrings(r["dependencies"]);
        if (!ParseU64Field(r, "size_bytes", rec.size_bytes, rec.size_known)) {
            return Fail(err_code, err, "MISSING_RESOURCE", "size_bytes");
        }
        auto it = by_id.find(rec.id);
        if (it != by_id.end()) {
            std::string e1, e2;
            std::vector<unsigned char> a, b;
            if (!EncodePjson1(*it->second.obj, a, e1) || !EncodePjson1(r, b, e2) || a != b) {
                return Fail(err_code, err, "DUPLICATE_ID", "duplicate resource id with conflicting commitments");
            }
            return Fail(err_code, err, "DUPLICATE_ID", "duplicate resource id");
        }
        by_id.emplace(rec.id, std::move(rec));
    }
    return true;
}

bool WalkDeps(const std::string& id, const std::map<std::string, ResourceRec>& by_id,
              std::map<std::string, int>& color, int depth, size_t& nodes,
              std::string& err_code, std::string& err)
{
    auto it = by_id.find(id);
    if (it == by_id.end()) {
        return Fail(err_code, err, "MISSING_RESOURCE", "missing resource ref " + id);
    }
    if (depth > kMaxDepDepth) {
        return Fail(err_code, err, "DEPENDENCY_CYCLE", "dependency depth exceeded");
    }
    int& col = color[id];
    if (col == 1) {
        return Fail(err_code, err, "DEPENDENCY_CYCLE", "dependency cycle");
    }
    if (col == 2) return true;
    col = 1;
    if (++nodes > kMaxDepNodes) {
        return Fail(err_code, err, "DEPENDENCY_CYCLE", "dependency node limit");
    }
    for (const auto& child : it->second.deps) {
        if (!WalkDeps(child, by_id, color, depth + 1, nodes, err_code, err)) return false;
    }
    col = 2;
    return true;
}

bool ValidateResourceGraph(const std::map<std::string, ResourceRec>& by_id, std::string& err_code, std::string& err)
{
    std::map<std::string, int> color;
    size_t nodes = 0;
    for (const auto& e : by_id) {
        if (!WalkDeps(e.first, by_id, color, 0, nodes, err_code, err)) return false;
    }
    return true;
}

bool IndexVariants(const UniValue& core, const std::map<std::string, ResourceRec>& by_id,
                   std::vector<VariantRec>& out, std::string& err_code, std::string& err)
{
    out.clear();
    if (!core.exists("variants")) return true;
    if (!core["variants"].isArray()) {
        return Fail(err_code, err, "NO_COMPATIBLE_VARIANT", "variants must be an array");
    }
    const auto& arr = core["variants"].getValues();
    if (arr.size() > kMaxVariants) {
        return Fail(err_code, err, "NO_COMPATIBLE_VARIANT", "variant count");
    }
    std::set<std::string> seen;
    for (const auto& v : arr) {
        if (!v.isObject() || !v.exists("variant_id") || !v["variant_id"].isStr()) {
            return Fail(err_code, err, "NO_COMPATIBLE_VARIANT", "variant_id");
        }
        VariantRec rec;
        rec.obj = &v;
        rec.variant_id = v["variant_id"].get_str();
        if (!seen.insert(rec.variant_id).second) {
            return Fail(err_code, err, "DUPLICATE_ID", "duplicate variant_id");
        }
        if (!v.exists("resource_id") || !v["resource_id"].isStr()) {
            return Fail(err_code, err, "MISSING_RESOURCE", "variant resource_id");
        }
        rec.resource_id = v["resource_id"].get_str();
        auto rit = by_id.find(rec.resource_id);
        if (rit == by_id.end()) {
            return Fail(err_code, err, "MISSING_RESOURCE", "variant missing resource ref");
        }
        if (rit->second.kind != "MODEL") {
            return Fail(err_code, err, "MISSING_RESOURCE", "variant must name a MODEL resource");
        }
        rec.format = v.exists("format") && v["format"].isStr() ? v["format"].get_str() : std::string{};
        if (v.exists("dependencies")) rec.deps = AsStrings(v["dependencies"]);
        for (const auto& d : rec.deps) {
            if (!by_id.count(d)) {
                return Fail(err_code, err, "MISSING_RESOURCE", "variant missing dependency");
            }
        }
        if (v.exists("runtime_profile_ids")) rec.runtime_profile_ids = AsStrings(v["runtime_profile_ids"]);
        if (v.exists("compatibility") && v["compatibility"].isObject()) {
            const UniValue& c = v["compatibility"];
            rec.architectures = AsStrings(c.exists("architectures") ? c["architectures"] : UniValue{UniValue::VARR});
            rec.operating_systems = AsStrings(c.exists("operating_systems") ? c["operating_systems"] : UniValue{UniValue::VARR});
            rec.backends = AsStrings(c.exists("backends") ? c["backends"] : UniValue{UniValue::VARR});
            if (!ParseU64Field(c, "minimum_ram_bytes", rec.min_ram, rec.min_ram_known)) {
                return Fail(err_code, err, "NO_COMPATIBLE_VARIANT", "minimum_ram_bytes");
            }
            if (!ParseU64Field(c, "minimum_vram_bytes", rec.min_vram, rec.min_vram_known)) {
                return Fail(err_code, err, "NO_COMPATIBLE_VARIANT", "minimum_vram_bytes");
            }
            if (!ParseU64Field(c, "weight_bytes", rec.weight_bytes, rec.weight_known)) {
                return Fail(err_code, err, "NO_COMPATIBLE_VARIANT", "weight_bytes");
            }
            if (!ParseU64Field(c, "kv_overhead_bytes", rec.kv_overhead_bytes, rec.kv_known)) {
                return Fail(err_code, err, "NO_COMPATIBLE_VARIANT", "kv_overhead_bytes");
            }
            if (!ParseU64Field(c, "runtime_overhead_bytes", rec.runtime_overhead_bytes, rec.runtime_known)) {
                return Fail(err_code, err, "NO_COMPATIBLE_VARIANT", "runtime_overhead_bytes");
            }
        }
        if (!rec.weight_known && rit->second.size_known) {
            rec.weight_bytes = rit->second.size_bytes;
            rec.weight_known = true;
        }
        out.push_back(std::move(rec));
    }
    return true;
}

bool PackageType(const UniValue& core, std::string& out)
{
    return FieldStr(core, "package_type", out);
}

bool IsBountyWithoutModel(const UniValue& core, const std::map<std::string, ResourceRec>& by_id,
                          const std::vector<VariantRec>& variants)
{
    std::string t;
    PackageType(core, t);
    if (t != "BOUNTY") return false;
    if (!variants.empty()) return false;
    for (const auto& e : by_id) {
        if (e.second.kind == "MODEL") return false;
    }
    return true;
}

bool HasBountyRef(const UniValue& core)
{
    if (!core.exists("economy_refs") || !core["economy_refs"].isArray()) return false;
    for (const auto& r : core["economy_refs"].getValues()) {
        if (r.isObject() && r.exists("kind") && r["kind"].isStr() && r["kind"].get_str() == "BOUNTY") {
            return true;
        }
    }
    return false;
}

/** Spec §5.2: never rank by CUDA/vendor. Same predicates for every backend family. */
uint64_t SatAdd(uint64_t a, uint64_t b)
{
    if (a > std::numeric_limits<uint64_t>::max() - b) return std::numeric_limits<uint64_t>::max();
    return a + b;
}

uint64_t EffectiveRamBytes(const VariantRec& v)
{
    uint64_t complete = 0;
    if (v.weight_known) complete = SatAdd(complete, v.weight_bytes);
    if (v.kv_known) complete = SatAdd(complete, v.kv_overhead_bytes);
    if (v.runtime_known) complete = SatAdd(complete, v.runtime_overhead_bytes);
    if (v.min_ram_known) return std::max(v.min_ram, complete);
    return complete;
}

bool RamEstimateKnown(const VariantRec& v)
{
    return v.min_ram_known || v.weight_known || v.kv_known || v.runtime_known;
}

bool VariantEligible(const VariantRec& v, const UniValue& local_obs)
{
    std::vector<std::string> have;
    bool present = false;

    ObsList(local_obs, "architectures", "architecture", have, present);
    if (!IntersectsOrUnconstrained(v.architectures, have, present)) return false;

    ObsList(local_obs, "operating_systems", "operating_system", have, present);
    if (!IntersectsOrUnconstrained(v.operating_systems, have, present)) return false;

    ObsList(local_obs, "backends", "backend", have, present);
    if (!IntersectsOrUnconstrained(v.backends, have, present)) return false;

    ObsList(local_obs, "supported_formats", "format", have, present);
    if (present && !v.format.empty()) {
        if (std::find(have.begin(), have.end(), v.format) == have.end()) return false;
    }

    ObsList(local_obs, "runtime_profile_ids", "runtime_profile_id", have, present);
    if (!IntersectsOrUnconstrained(v.runtime_profile_ids, have, present)) return false;

    uint64_t avail = 0;
    bool avail_present = false;
    if (!ParseU64Field(local_obs, "available_ram_bytes", avail, avail_present)) return false;
    if (avail_present && RamEstimateKnown(v) && EffectiveRamBytes(v) > avail) return false;

    uint64_t vram = 0;
    bool vram_present = false;
    if (!ParseU64Field(local_obs, "available_vram_bytes", vram, vram_present)) return false;
    if (vram_present && v.min_vram_known && v.min_vram > vram) return false;

    return true;
}

const VariantRec* FindVariant(const std::vector<VariantRec>& vs, const std::string& id)
{
    for (const auto& v : vs) {
        if (v.variant_id == id) return &v;
    }
    return nullptr;
}

std::string Tradeoff(const UniValue& obs)
{
    std::string t;
    if (FieldStr(obs, "tradeoff", t)) return t;
    return "stable";
}

const VariantRec* PickStable(const std::vector<const VariantRec*>& eligible, const std::string& tradeoff)
{
    if (eligible.empty()) return nullptr;
    const VariantRec* best = eligible.front();
    const bool by_mem = (tradeoff == "memory" || tradeoff == "ram");
    for (const auto* v : eligible) {
        if (by_mem) {
            const uint64_t a = RamEstimateKnown(*best) ? EffectiveRamBytes(*best) : std::numeric_limits<uint64_t>::max();
            const uint64_t b = RamEstimateKnown(*v) ? EffectiveRamBytes(*v) : std::numeric_limits<uint64_t>::max();
            if (b < a) {
                best = v;
                continue;
            }
            if (b > a) continue;
        }
        if (v->variant_id < best->variant_id) best = v;
    }
    return best;
}

bool LoadGraph(const UniValue& core, std::map<std::string, ResourceRec>& by_id,
               std::vector<VariantRec>& variants, std::string& err_code, std::string& err)
{
    if (!IndexResources(core, by_id, err_code, err)) return false;
    if (!ValidateResourceGraph(by_id, err_code, err)) return false;
    if (!IndexVariants(core, by_id, variants, err_code, err)) return false;
    return true;
}

bool PaidConversionAttempt(const UniValue& policy)
{
    if (!policy.isObject()) return false;
    if (policy.exists("auto_pay") && policy["auto_pay"].isTrue()) return true;
    if (policy.exists("convert_to_paid") && policy["convert_to_paid"].isTrue()) return true;
    if (policy.exists("purchase") && policy["purchase"].isTrue()) return true;
    if (policy.exists("retrieval_mode") && policy["retrieval_mode"].isStr()) {
        if (policy["retrieval_mode"].get_str() != "FREE_ONLY") return true;
    }
    for (const char* k : {"budget_atoms", "price_atoms", "pay_atoms", "automatic_spend_atoms"}) {
        if (!policy.exists(k)) continue;
        const std::string s = AsStr(policy[k]);
        uint64_t n = 0;
        if (ParseUInt64(s, &n) && n > 0) return true;
    }
    return false;
}

bool AwaitingPublicRelease(const UniValue& policy)
{
    if (!policy.isObject()) return false;
    if (policy.exists("awaiting_public_release") && policy["awaiting_public_release"].isTrue()) return true;
    std::string st;
    if (FieldStr(policy, "release_state", st)) {
        if (st == "WAITING_FOR_PUBLIC_RELEASE" || st == "PAID_RELEASE") return true;
    }
    return false;
}

bool DestinationOk(const std::string& dest, std::string& err_code, std::string& err)
{
    if (dest.empty()) {
        return Fail(err_code, err, "DESTINATION_REQUIRED", "destination required");
    }
    if (dest.find("://") != std::string::npos) {
        return Fail(err_code, err, "DESTINATION_REQUIRED", "destination must be a local path; will not fetch arbitrary code");
    }
    return true;
}

void CollectResourceIds(const VariantRec& v, const std::map<std::string, ResourceRec>& by_id,
                        std::vector<std::string>& ids)
{
    std::set<std::string> seen;
    std::vector<std::string> stack{v.resource_id};
    stack.insert(stack.end(), v.deps.begin(), v.deps.end());
    while (!stack.empty()) {
        const std::string id = std::move(stack.back());
        stack.pop_back();
        if (!seen.insert(id).second) continue;
        ids.push_back(id);
        auto it = by_id.find(id);
        if (it == by_id.end()) continue;
        for (const auto& d : it->second.deps) stack.push_back(d);
    }
    std::sort(ids.begin(), ids.end());
}

} // namespace

bool AcquisitionPlanDigest(const AcquisitionPlan& plan, Digest48& out, std::string& err)
{
    out = {};
    if (!plan.json.isObject()) {
        err = "plan json";
        return false;
    }
    const UniValue body = OmitKeys(plan.json, {"plan_id", "authorization_ref"});
    return DomainPlanDigest(ACQUISITION_PLAN_DOMAIN, body, out, err);
}

bool SelectPackageVariant(const UniValue& core_in, const UniValue& local_obs, std::string& variant_id,
                          std::string& err_code, std::string& err)
{
    variant_id.clear();
    err_code.clear();
    err.clear();
    const UniValue& core = CoreObj(core_in);
    if (!core.isObject()) {
        return Fail(err_code, err, "NO_COMPATIBLE_VARIANT", "core object");
    }

    std::map<std::string, ResourceRec> by_id;
    std::vector<VariantRec> variants;
    if (!LoadGraph(core, by_id, variants, err_code, err)) return false;

    if (variants.empty()) {
        if (IsBountyWithoutModel(core, by_id, variants) && HasBountyRef(core)) {
            variant_id.clear();
            return true;
        }
        return Fail(err_code, err, "NO_COMPATIBLE_VARIANT",
                    "no compatible variant; will not fetch arbitrary code");
    }

    std::vector<const VariantRec*> eligible;
    eligible.reserve(variants.size());
    for (const auto& v : variants) {
        if (VariantEligible(v, local_obs)) eligible.push_back(&v);
    }

    std::string explicit_id;
    if (FieldStr(local_obs, "explicit_variant", explicit_id) ||
        FieldStr(local_obs, "user_variant", explicit_id) ||
        FieldStr(local_obs, "variant_id", explicit_id)) {
        const VariantRec* chosen = FindVariant(variants, explicit_id);
        if (!chosen || std::find(eligible.begin(), eligible.end(), chosen) == eligible.end()) {
            return Fail(err_code, err, "NO_COMPATIBLE_VARIANT",
                        "explicit variant is not compatible; will not fetch arbitrary code");
        }
        variant_id = chosen->variant_id;
        return true;
    }

    std::string pref;
    if (FieldStr(local_obs, "preferred_variant", pref)) {
        const VariantRec* chosen = FindVariant(variants, pref);
        if (chosen && std::find(eligible.begin(), eligible.end(), chosen) != eligible.end()) {
            variant_id = chosen->variant_id;
            return true;
        }
    }

    const VariantRec* picked = PickStable(eligible, Tradeoff(local_obs));
    if (!picked) {
        return Fail(err_code, err, "NO_COMPATIBLE_VARIANT",
                    "no compatible variant; will not fetch arbitrary code");
    }
    variant_id = picked->variant_id;
    return true;
}

bool PlanBtxAcquisition(const UniValue& core_in, const UniValue& local_policy, AcquisitionPlan& out,
                        std::string& err_code, std::string& err)
{
    out = {};
    err_code.clear();
    err.clear();
    const UniValue& core = CoreObj(core_in);
    if (!core.isObject()) {
        return Fail(err_code, err, "NO_COMPATIBLE_VARIANT", "core object");
    }

    if (PaidConversionAttempt(local_policy)) {
        return Fail(err_code, err, "PAID_CONVERSION_REJECTED",
                    "FREE_ONLY plan refuses silent paid conversion");
    }
    if (AwaitingPublicRelease(local_policy)) {
        return Fail(err_code, err, "WAITING_FOR_PUBLIC_RELEASE",
                    "WAITING_FOR_PUBLIC_RELEASE; spend remains zero");
    }

    std::map<std::string, ResourceRec> by_id;
    std::vector<VariantRec> variants;
    if (!LoadGraph(core, by_id, variants, err_code, err)) return false;

    const bool bounty_preview = IsBountyWithoutModel(core, by_id, variants) && HasBountyRef(core);

    std::string dest;
    FieldStr(local_policy, "destination", dest);
    if (!bounty_preview) {
        if (!DestinationOk(dest, err_code, err)) return false;
    } else if (!dest.empty()) {
        if (!DestinationOk(dest, err_code, err)) return false;
    }

    std::string source_policy = "NATIVE_ONLY";
    if (local_policy.isObject() && local_policy.exists("source_policy") && local_policy["source_policy"].isStr()) {
        source_policy = local_policy["source_policy"].get_str();
        if (source_policy != "NATIVE_ONLY" && source_policy != "LOCAL_POLICY") {
            return Fail(err_code, err, "NATIVE_SOURCES_UNAVAILABLE",
                        "source_policy must be NATIVE_ONLY or LOCAL_POLICY");
        }
    }

    std::string variant_id;
    if (!SelectPackageVariant(core, local_policy, variant_id, err_code, err)) return false;

    std::vector<std::string> resource_ids;
    if (!variant_id.empty()) {
        const VariantRec* v = FindVariant(variants, variant_id);
        if (!v) {
            return Fail(err_code, err, "NO_COMPATIBLE_VARIANT", "selected variant disappeared");
        }
        CollectResourceIds(*v, by_id, resource_ids);
    }

    std::string network = "REGTEST";
    FieldStr(core, "network", network);

    std::string expires = "0";
    FieldStr(local_policy, "expires_at_ms", expires);
    std::string max_bytes = "0";
    FieldStr(local_policy, "maximum_download_bytes", max_bytes);

    int64_t max_seconds = 3600;
    if (local_policy.isObject() && local_policy.exists("maximum_seconds")) {
        const std::string s = AsStr(local_policy["maximum_seconds"]);
        int64_t n = 0;
        if (!ParseInt64(s, &n) || n < 1 || n > 604800) {
            return Fail(err_code, err, "BUDGET_EXCEEDED", "maximum_seconds");
        }
        max_seconds = n;
    }

    std::string seed_policy = "OFF";
    FieldStr(local_policy, "seed_policy", seed_policy);
    if (seed_policy != "OFF" && seed_policy != "EXISTING_LOCAL_POLICY" && seed_policy != "EXPLICIT_ON") {
        seed_policy = "OFF";
    }
    std::string retention = "CACHE";
    FieldStr(local_policy, "retention_policy", retention);
    if (retention != "CACHE" && retention != "KEEP" && retention != "ACTIVE_LEASE") {
        retention = "CACHE";
    }

    if (!PackageCoreId(core, out.package_core_id, err)) {
        err_code = "NONCANONICAL_PAYLOAD";
        return false;
    }

    UniValue body(UniValue::VOBJ);
    body.pushKV("schema_version", 1);
    body.pushKV("package_core_id", out.package_core_id.Hex());
    body.pushKV("network", network);
    body.pushKV("expires_at_ms", expires);
    UniValue rids(UniValue::VARR);
    for (const auto& id : resource_ids) rids.push_back(id);
    body.pushKV("resource_ids", rids);
    if (!dest.empty()) body.pushKV("destination", dest);
    if (!variant_id.empty()) body.pushKV("variant_id", variant_id);
    body.pushKV("retrieval_mode", "FREE_ONLY");
    body.pushKV("source_policy", source_policy);
    body.pushKV("maximum_download_bytes", max_bytes);
    body.pushKV("maximum_seconds", max_seconds);
    body.pushKV("seed_policy", seed_policy);
    body.pushKV("retention_policy", retention);

    Digest48 digest;
    if (!DomainPlanDigest(ACQUISITION_PLAN_DOMAIN, body, digest, err)) {
        err_code = "NONCANONICAL_PAYLOAD";
        return false;
    }

    out.plan_id_hex = digest.Hex();
    out.network = network;
    out.variant_id = variant_id;
    out.resource_ids = std::move(resource_ids);
    out.destination = dest;
    out.retrieval_mode = "FREE_ONLY";
    out.source_policy = source_policy;
    out.expires_at_ms = expires;
    out.json = body;
    out.json.pushKV("plan_id", out.plan_id_hex);
    return true;
}

} // namespace modelnet
