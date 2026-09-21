// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Worker H: predictive prefetch, executable-cache policy, private prefix KV.
// Real AdmitPrefetchHint / AcceptExecutableCache / PrivatePrefixKey /
// PrefixVisibleToTenant live here. Coordinator must not reintroduce the four
// stubs in capability_exec.cpp (duplicate symbols after this TU is linked).

#include <modelnet/capability.h>

#include <util/strencodings.h>
#include <util/string.h>
#include <util/time.h>

#include <cstdlib>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {
namespace {

std::mutex g_mu;

bool Fail(std::string& err_code, std::string& err, const char* code, const std::string& msg)
{
    err_code = code;
    err = msg.empty() ? code : msg;
    return false;
}

uint64_t ParseU64(const UniValue& v, uint64_t fallback = 0)
{
    if (v.isNum()) return v.getInt<uint64_t>();
    if (v.isStr()) {
        const char* s = v.get_str().c_str();
        char* end = nullptr;
        const unsigned long long n = std::strtoull(s, &end, 10);
        if (end && end != s) return static_cast<uint64_t>(n);
    }
    return fallback;
}

int64_t ParseI64(const UniValue& v, int64_t fallback = 0)
{
    if (v.isNum()) return v.getInt<int64_t>();
    if (v.isStr()) {
        const char* s = v.get_str().c_str();
        char* end = nullptr;
        const long long n = std::strtoll(s, &end, 10);
        if (end && end != s) return static_cast<int64_t>(n);
    }
    return fallback;
}

uint64_t FieldU64(const UniValue& o, const char* k, uint64_t fallback = 0)
{
    if (!o.exists(k)) return fallback;
    return ParseU64(o[k], fallback);
}

int64_t FieldI64(const UniValue& o, const char* k, int64_t fallback = 0)
{
    if (!o.exists(k)) return fallback;
    return ParseI64(o[k], fallback);
}

bool Truthy(const UniValue& o, const char* k)
{
    if (!o.exists(k)) return false;
    const UniValue& v = o[k];
    if (v.isTrue()) return true;
    if (v.isBool()) return v.get_bool();
    if (v.isStr()) {
        const std::string s = v.get_str();
        return s == "1" || s == "true" || s == "TRUE" || s == "DEMAND";
    }
    return false;
}

bool IsDemandHint(const UniValue& hint)
{
    if (Truthy(hint, "demand") || Truthy(hint, "urgent")) return true;
    if (hint.exists("priority") && hint["priority"].isStr()) {
        const std::string p = hint["priority"].get_str();
        return p == "DEMAND" || p == "demand" || p == "URGENT";
    }
    if (hint.exists("class") && hint["class"].isStr()) {
        return hint["class"].get_str() == "DEMAND";
    }
    return false;
}

bool HintHasPrivateTranscript(const UniValue& hint)
{
    static const char* kBanned[] = {
        "prompt_transcript", "reasoning_transcript", "agent_scratchpad",
        "planning_context", "chain_of_thought", "full_reasoning",
    };
    for (const char* k : kBanned) {
        if (hint.exists(k)) return true;
    }
    return false;
}

std::string RecipeOf(const UniValue& hint)
{
    if (hint.exists("recipe_id") && hint["recipe_id"].isStr()) return hint["recipe_id"].get_str();
    if (hint.exists("recipe_ids") && hint["recipe_ids"].isArray() && hint["recipe_ids"].size() > 0 &&
        hint["recipe_ids"][0].isStr()) {
        return hint["recipe_ids"][0].get_str();
    }
    return "unspecified";
}

void CopyKV(UniValue& dst, const UniValue& src, const char* k)
{
    if (src.exists(k)) dst.pushKV(k, src[k]);
}

std::string CanonicalTenantId(const std::string& tenant)
{
    return std::string(util::TrimStringView(tenant));
}

bool TenantIdUsable(const std::string& tenant)
{
    const std::string t = CanonicalTenantId(tenant);
    if (t.empty() || t == "*") return false;
    const std::string u = ToUpper(t);
    if (u == "ANY" || u == "ANON" || u == "ANONYMOUS") return false;
    if (u == "PUBLIC" || u == "PUBLIC_MODEL" || u == "PUBLIC_RELEASED") return false;
    if (u == "LOCAL_USER" || u == "ORGANIZATION" || u == "RUNTIME_PROCESS") return false;
    return true;
}

bool RejectPaidPath(const UniValue& o, std::string& err_code, std::string& err)
{
    if (!o.exists("automatic_spend_atoms")) return false;
    if (ParseI64(o["automatic_spend_atoms"], 0) == 0) return false;
    Fail(err_code, err, "PAID_PATH_FORBIDDEN", "automatic_spend_atoms must remain 0");
    return true;
}

bool ScopeIsPublicShared(const UniValue& o)
{
    if (!o.exists("scope") || !o["scope"].isStr()) return false;
    const std::string u = ToUpper(std::string(util::TrimStringView(o["scope"].get_str())));
    return u == "PUBLIC" || u == "PUBLIC_MODEL" || u == "PUBLIC_RELEASED";
}

bool ClaimsModelAuthorSignature(const UniValue& cache)
{
    if (!cache.exists("verification_method") || !cache["verification_method"].isStr()) return false;
    return ToUpper(cache["verification_method"].get_str()) == "MODEL_AUTHOR_SIGNATURE";
}

std::string TenantOf(const UniValue& o)
{
    static const char* kKeys[] = {"tenant", "owner_tenant"};
    for (const char* k : kKeys) {
        if (!o.exists(k) || !o[k].isStr()) continue;
        return o[k].get_str();
    }
    return {};
}

std::string RequesterOf(const UniValue& o)
{
    if (o.exists("requester") && o["requester"].isStr()) return o["requester"].get_str();
    return TenantOf(o);
}

int64_t NowMs()
{
    return TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
}

UniValue FingerprintBody(const UniValue& cache)
{
    UniValue fp(UniValue::VOBJ);
    const UniValue* rt = (cache.exists("runtime") && cache["runtime"].isObject()) ? &cache["runtime"] : nullptr;
    if (cache.exists("compiler")) fp.pushKV("compiler", cache["compiler"]);
    else if (rt && rt->exists("compiler")) fp.pushKV("compiler", (*rt)["compiler"]);
    if (cache.exists("runtime_id")) fp.pushKV("runtime_id", cache["runtime_id"]);
    else if (cache.exists("runtime") && cache["runtime"].isStr()) fp.pushKV("runtime_id", cache["runtime"]);
    else if (rt && rt->exists("runtime_id")) fp.pushKV("runtime_id", (*rt)["runtime_id"]);
    CopyKV(fp, cache, "dtype");
    CopyKV(fp, cache, "shape");
    // Model identity is not a recipe identity. Aliasing source_recipe_id onto
    // model_digest collapsed distinct derived executables into one slot.
    if (cache.exists("model_digest")) fp.pushKV("model_digest", cache["model_digest"]);
    else if (cache.exists("model_id")) fp.pushKV("model_digest", cache["model_id"]);
    // recipe_id is stripped by CapabilityObjectIdJson; rebind as source_recipe_id.
    if (cache.exists("source_recipe_id")) fp.pushKV("source_recipe_id", cache["source_recipe_id"]);
    else if (cache.exists("recipe_id")) fp.pushKV("source_recipe_id", cache["recipe_id"]);
    CopyKV(fp, cache, "adapters");
    CopyKV(fp, cache, "adapter_order");
    CopyKV(fp, cache, "adapter_fingerprint");
    if (cache.exists("tenant") && cache["tenant"].isStr()) {
        fp.pushKV("tenant", CanonicalTenantId(cache["tenant"].get_str()));
    }
    if (cache.exists("owner_tenant") && cache["owner_tenant"].isStr()) {
        fp.pushKV("owner_tenant", CanonicalTenantId(cache["owner_tenant"].get_str()));
    }
    CopyKV(fp, cache, "tenant_key_id");
    CopyKV(fp, cache, "scope");
    return fp;
}

bool HasGraphPointers(const UniValue& cache)
{
    if (Truthy(cache, "contains_generation_pointers") || Truthy(cache, "generation_pointers") ||
        Truthy(cache, "live_graph") || Truthy(cache, "graph_capture") ||
        Truthy(cache, "cuda_graph") || Truthy(cache, "process_generation_pointers")) {
        return true;
    }
    if (cache.exists("format") && cache["format"].isStr()) {
        const std::string f = cache["format"].get_str();
        if (f == "cuda_graph" || f == "live_graph" || f == "captured_graph") return true;
    }
    return false;
}

bool UnsafeCacheFormat(const UniValue& cache)
{
    if (!cache.exists("format") || !cache["format"].isStr()) return false;
    const std::string f = cache["format"].get_str();
    return f == "pickle" || f == "so" || f == "unknown" || f == "dll" || f == "dylib";
}

bool IsLocalBuild(const UniValue& cache)
{
    if (cache.exists("verification_method") && cache["verification_method"].isStr()) {
        const std::string m = cache["verification_method"].get_str();
        if (m == "LOCAL_BUILD" || m == "EXACT_RECOMPUTE") return true;
    }
    if (cache.exists("source") && cache["source"].isStr()) {
        const std::string s = cache["source"].get_str();
        if (s == "local_compile" || s == "local_build") return true;
    }
    return false;
}

struct PrefetchJob {
    std::string job_id;
    const HostResourceBroker* broker{nullptr};
    bool demand{false};
    bool dispatched{false};
    bool cancelled{false};
    bool finished{false};
    bool slot{false};
    bool reserved{false};
    bool fence{false};
    uint64_t host{0};
    uint64_t pinned{0};
    uint64_t device{0};
    int64_t expires_at_ms{0};
    std::string actor;
    std::string recipe;
    std::string desired_tier;
    uint64_t wasted_bytes{0};
    bool used{false};
};

struct PrefetchState {
    std::vector<PrefetchJob> jobs;
    std::map<const HostResourceBroker*, uint64_t> speculative_used;
    std::map<const HostResourceBroker*, std::string> last_recipe;
    std::map<const HostResourceBroker*, int64_t> last_admit_ms;
    uint64_t hits{0};
    uint64_t wasted_bytes{0};
    uint64_t avoided_latency_ms{0};
    uint64_t abandoned{0};
    uint64_t admitted{0};
    uint64_t speculative_evictions{0};
    uint64_t thrash_rejects{0};
};

PrefetchState g_pf;

struct CacheEntry {
    Digest48 fingerprint{};
    UniValue body;
    bool committed{false};
    std::string owner;
};

std::map<std::string, CacheEntry> g_cache;

struct KvEntry {
    std::string owner;
    Digest48 key{};
    UniValue payload;
    bool complete{false};
    bool persist_complete{false};
    bool retired{false};
    int64_t expires_at_ms{0};
};

std::map<std::string, KvEntry> g_kv;
std::map<std::string, uint64_t> g_tenant_epoch;

uint64_t TenantEpoch(const std::string& tenant)
{
    auto it = g_tenant_epoch.find(tenant);
    return it == g_tenant_epoch.end() ? 0 : it->second;
}

PrefetchJob* FindJob(const std::string& job_id)
{
    for (auto& j : g_pf.jobs) {
        if (j.job_id == job_id) return &j;
    }
    return nullptr;
}

uint64_t SpeculativeCap(const UniValue& hint, const LocalCapabilityGrant& grant)
{
    if (hint.exists("speculative_pool_bytes")) return FieldU64(hint, "speculative_pool_bytes", 0);
    if (grant.json.isObject() && grant.json.exists("memory") && grant.json["memory"].isObject() &&
        grant.json["memory"].exists("speculative_bytes")) {
        return ParseU64(grant.json["memory"]["speculative_bytes"], 0);
    }
    if (grant.host_bytes) return (grant.host_bytes * static_cast<uint64_t>(PREFETCH_BUDGET_PERCENT)) / 100;
    return FieldU64(hint, "max_speculative_bytes", 0);
}

void ReleaseJobLocked(PrefetchJob& j, HostResourceBroker& broker, bool drop_slot, bool drop_reserve)
{
    if (drop_reserve && j.reserved) {
        broker.Release(j.host, j.pinned, j.device, !j.demand);
        if (!j.demand) {
            auto it = g_pf.speculative_used.find(j.broker);
            if (it != g_pf.speculative_used.end()) {
                if (it->second >= j.host + j.device) it->second -= j.host + j.device;
                else it->second = 0;
            }
        }
        j.reserved = false;
    }
    if (drop_slot && j.slot) {
        broker.FinishPrefetch();
        j.slot = false;
    }
}

int PreemptQueuedSpeculative(HostResourceBroker& broker, uint64_t need_host)
{
    int n = 0;
    uint64_t freed = 0;
    for (auto& j : g_pf.jobs) {
        if (j.broker != &broker || j.demand || j.cancelled || j.finished) continue;
        if (j.dispatched || j.fence) continue;
        ReleaseJobLocked(j, broker, /*drop_slot=*/true, /*drop_reserve=*/true);
        j.cancelled = true;
        g_pf.speculative_evictions += 1;
        ++n;
        freed += j.host;
        if (need_host && freed >= need_host) break;
    }
    return n;
}

} // namespace

void ResetCapabilityPrefetchForTests()
{
    std::lock_guard<std::mutex> lock(g_mu);
    g_pf = {};
    g_cache.clear();
    g_kv.clear();
    g_tenant_epoch.clear();
}

bool DispatchPrefetchJob(const std::string& job_id, HostResourceBroker& broker, std::string& err_code, std::string& err)
{
    std::lock_guard<std::mutex> lock(g_mu);
    PrefetchJob* j = FindJob(job_id);
    if (!j || j->broker != &broker) return Fail(err_code, err, "INVALID_PARAMETER", "unknown prefetch job");
    if (j->cancelled) return Fail(err_code, err, "HINT_EXPIRED", "cancelled");
    j->dispatched = true;
    return true;
}

bool ExpirePrefetchHints(int64_t now_ms, HostResourceBroker& broker, UniValue& report)
{
    std::lock_guard<std::mutex> lock(g_mu);
    int cancelled_queued = 0;
    int charged_dispatched = 0;
    for (auto& j : g_pf.jobs) {
        if (j.broker != &broker || j.finished || j.cancelled) continue;
        if (j.expires_at_ms <= 0 || now_ms <= j.expires_at_ms) continue;
        if (!j.dispatched && !j.fence) {
            ReleaseJobLocked(j, broker, /*drop_slot=*/true, /*drop_reserve=*/true);
            j.cancelled = true;
            ++cancelled_queued;
        } else {
            ++charged_dispatched;
        }
    }
    report = UniValue(UniValue::VOBJ);
    report.pushKV("cancelled_queued", cancelled_queued);
    report.pushKV("dispatched_still_charged", charged_dispatched);
    report.pushKV("prefetch_jobs", broker.PrefetchJobs());
    report.pushKV("automatic_spend_atoms", 0);
    return true;
}

bool FinishPrefetchJob(const std::string& job_id, HostResourceBroker& broker, std::string& err_code, std::string& err)
{
    std::lock_guard<std::mutex> lock(g_mu);
    PrefetchJob* j = FindJob(job_id);
    if (!j || j->broker != &broker) return Fail(err_code, err, "INVALID_PARAMETER", "unknown prefetch job");
    if (!j->finished) {
        ReleaseJobLocked(*j, broker, /*drop_slot=*/j->slot, /*drop_reserve=*/j->reserved);
        j->finished = true;
    }
    return true;
}

bool RecordPrefetchOutcome(const std::string& job_id, bool used, uint64_t avoided_latency_ms, uint64_t wasted_bytes)
{
    std::lock_guard<std::mutex> lock(g_mu);
    PrefetchJob* j = FindJob(job_id);
    if (!j) return false;
    j->used = used;
    if (used) {
        g_pf.hits += 1;
        g_pf.avoided_latency_ms += avoided_latency_ms;
    } else {
        g_pf.abandoned += 1;
        const uint64_t w = wasted_bytes ? wasted_bytes : j->host;
        g_pf.wasted_bytes += w;
        j->wasted_bytes = w;
    }
    return true;
}

UniValue PrefetchMetricsJson()
{
    std::lock_guard<std::mutex> lock(g_mu);
    UniValue o(UniValue::VOBJ);
    o.pushKV("hits", std::to_string(g_pf.hits));
    o.pushKV("avoided_latency_ms", std::to_string(g_pf.avoided_latency_ms));
    o.pushKV("wasted_bytes", std::to_string(g_pf.wasted_bytes));
    o.pushKV("abandoned", std::to_string(g_pf.abandoned));
    o.pushKV("admitted", std::to_string(g_pf.admitted));
    o.pushKV("speculative_evictions", std::to_string(g_pf.speculative_evictions));
    o.pushKV("thrash_rejects", std::to_string(g_pf.thrash_rejects));
    o.pushKV("automatic_spend_atoms", 0);
    return o;
}

bool ExecutableCacheFingerprint(const UniValue& cache, Digest48& out, std::string& err)
{
    return CapabilityObjectIdJson(REPRESENTATION_DOMAIN, FingerprintBody(cache), out, err);
}

bool CommitExecutableCache(const UniValue& cache, bool crash_before_promote, UniValue& visible,
                           std::string& err_code, std::string& err)
{
    if (RejectPaidPath(cache, err_code, err)) return false;
    const std::string owner = CanonicalTenantId(TenantOf(cache));
    if ((cache.exists("tenant") || cache.exists("owner_tenant")) && !TenantIdUsable(owner)) {
        return Fail(err_code, err, "PREFIX_INCOMPATIBLE", "tenant isolation");
    }
    if (TenantIdUsable(owner) && ScopeIsPublicShared(cache)) {
        return Fail(err_code, err, "PREFIX_INCOMPATIBLE", "private derived cache is not a public model");
    }
    Digest48 fp{};
    if (!ExecutableCacheFingerprint(cache, fp, err)) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", err);
    }
    const std::string id = fp.Hex();
    std::lock_guard<std::mutex> lock(g_mu);
    if (crash_before_promote) {
        CacheEntry e;
        e.fingerprint = fp;
        e.body = cache;
        e.committed = false;
        e.owner = owner;
        g_cache[id + ":tmp"] = std::move(e);
        visible = UniValue(UniValue::VOBJ);
        visible.pushKV("visible", false);
        visible.pushKV("partial", true);
        visible.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    CacheEntry e;
    e.fingerprint = fp;
    e.body = cache;
    e.committed = true;
    e.owner = owner;
    g_cache[id] = std::move(e);
    g_cache.erase(id + ":tmp");
    visible = UniValue(UniValue::VOBJ);
    visible.pushKV("visible", true);
    visible.pushKV("partial", false);
    visible.pushKV("cache_id", id);
    visible.pushKV("automatic_spend_atoms", 0);
    return true;
}

bool LookupExecutableCache(const UniValue& query, UniValue& hit, std::string& err_code, std::string& err)
{
    Digest48 fp{};
    if (!ExecutableCacheFingerprint(query, fp, err)) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", err);
    }
    std::lock_guard<std::mutex> lock(g_mu);
    auto it = g_cache.find(fp.Hex());
    hit = UniValue(UniValue::VOBJ);
    hit.pushKV("automatic_spend_atoms", 0);
    // Cross-tenant denial uses the same CACHE_MISS as an empty slot so existence
    // of another tenant's derived executable is not disclosed.
    if (it == g_cache.end() || !it->second.committed) {
        hit.pushKV("hit", false);
        return Fail(err_code, err, "CACHE_MISS", "no committed cache");
    }
    const std::string owner = CanonicalTenantId(it->second.owner.empty() ? TenantOf(it->second.body) : it->second.owner);
    const std::string requester = CanonicalTenantId(RequesterOf(query));
    // Empty owner == empty requester used to pass. An unscoped slot is only
    // visible to an unscoped query; a tenant must not inherit a cache that
    // was never bound to it. Usable owners still require PrefixVisibleToTenant.
    if (TenantIdUsable(owner)) {
        if (!PrefixVisibleToTenant(owner, requester)) {
            hit.pushKV("hit", false);
            return Fail(err_code, err, "CACHE_MISS", "no committed cache");
        }
    } else if (TenantIdUsable(requester)) {
        hit.pushKV("hit", false);
        return Fail(err_code, err, "CACHE_MISS", "no committed cache");
    }
    hit.pushKV("hit", true);
    hit.pushKV("body", it->second.body);
    return true;
}

bool LocalCompileFallback(const UniValue& rejected, bool authorized, UniValue& result, std::string& err_code,
                          std::string& err)
{
    result = UniValue(UniValue::VOBJ);
    result.pushKV("automatic_spend_atoms", 0);
    result.pushKV("fetched_arbitrary_code", false);
    if (rejected.exists("remote_code_fetch") && rejected["remote_code_fetch"].isTrue()) {
        return Fail(err_code, err, "EXECUTABLE_CACHE_REJECTED", "do not silently fetch arbitrary code");
    }
    if (!authorized) {
        return Fail(err_code, err, "SOFTWARE_TRUST_REQUIRED", "local compile not authorized");
    }
    result.pushKV("compiled_locally", true);
    result.pushKV("source", "local_compile");
    result.pushKV("verification_method", "LOCAL_BUILD");
    return true;
}

bool MeasureWarmCacheBenefit(const UniValue& cold, const UniValue& warm, UniValue& report, std::string& err_code,
                             std::string& err)
{
    report = UniValue(UniValue::VOBJ);
    report.pushKV("automatic_spend_atoms", 0);
    auto same = [&](const char* k) {
        if (!cold.exists(k) && !warm.exists(k)) return true;
        if (!cold.exists(k) || !warm.exists(k)) return false;
        return cold[k].write() == warm[k].write();
    };
    if (!same("layers") || !same("quant") || !same("workload") || !same("model_digest")) {
        return Fail(err_code, err, "SYNTHETIC_PASS_FORBIDDEN", "warm/cold workload not equal");
    }
    const int64_t cold_ms = FieldI64(cold, "startup_ms", 0);
    const int64_t warm_ms = FieldI64(warm, "startup_ms", 0);
    const int64_t saved = cold_ms - warm_ms;
    report.pushKV("cold_startup_ms", std::to_string(cold_ms));
    report.pushKV("warm_startup_ms", std::to_string(warm_ms));
    report.pushKV("saved_ms", std::to_string(saved));
    report.pushKV("cache_source", warm.exists("cache_source") && warm["cache_source"].isStr() ?
                                      warm["cache_source"].get_str() :
                                      "local");
    report.pushKV("correctness_match", same("output_digest"));
    report.pushKV("synthetic_pass", false);
    if (saved < 0) {
        return Fail(err_code, err, "NO_WARM_BENEFIT", "warm path not faster");
    }
    return true;
}

bool PutPrivatePrefix(const std::string& tenant, const UniValue& config_fingerprint, const std::string& token_prefix,
                      const UniValue& state, std::string& err_code, std::string& err)
{
    const std::string owner = CanonicalTenantId(tenant);
    if (!TenantIdUsable(owner)) {
        return Fail(err_code, err, "PREFIX_INCOMPATIBLE", "tenant isolation");
    }
    if (RejectPaidPath(state, err_code, err)) return false;
    Digest48 key{};
    if (!PrivatePrefixKey(owner, config_fingerprint, token_prefix, key, err)) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", err);
    }
    const int complete_layers = state.exists("complete_layers") && state["complete_layers"].isNum() ?
                                    state["complete_layers"].getInt<int>() :
                                    0;
    const int expected_layers = state.exists("expected_layers") && state["expected_layers"].isNum() ?
                                    state["expected_layers"].getInt<int>() :
                                    0;
    const bool crash = Truthy(state, "crash_mid_persist");
    const bool persist_complete = state.exists("persist_complete") ? Truthy(state, "persist_complete") : !crash;
    const bool complete = persist_complete && !crash &&
                          (expected_layers <= 0 || complete_layers >= expected_layers);
    std::lock_guard<std::mutex> lock(g_mu);
    KvEntry e;
    e.owner = owner;
    e.key = key;
    e.payload = state;
    e.complete = complete;
    e.persist_complete = persist_complete && !crash;
    e.retired = false;
    e.expires_at_ms = FieldI64(state, "expires_at_ms", 0);
    g_kv[key.Hex()] = std::move(e);
    err_code.clear();
    err.clear();
    return true;
}

bool GetPrivatePrefix(const std::string& requester, const std::string& owner_tenant, const UniValue& config_fingerprint,
                      const std::string& token_prefix, UniValue& state, std::string& err_code, std::string& err)
{
    state = UniValue(UniValue::VOBJ);
    auto deny = [&]() {
        // Same code and message for isolation miss, empty slot, and expiry so a
        // second tenant cannot distinguish another tenant's prefix existence.
        return Fail(err_code, err, "PREFIX_INCOMPATIBLE", "unavailable");
    };
    if (!PrefixVisibleToTenant(owner_tenant, requester)) return deny();
    Digest48 key{};
    if (!PrivatePrefixKey(CanonicalTenantId(owner_tenant), config_fingerprint, token_prefix, key, err)) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", err);
    }
    std::lock_guard<std::mutex> lock(g_mu);
    auto it = g_kv.find(key.Hex());
    if (it == g_kv.end() || it->second.retired || !it->second.complete || !it->second.persist_complete) {
        return deny();
    }
    if (!PrefixVisibleToTenant(it->second.owner, requester)) return deny();
    if (it->second.expires_at_ms > 0 && NowMs() >= it->second.expires_at_ms) {
        return deny();
    }
    state = it->second.payload;
    if (!state.exists("saved_prefill_work")) state.pushKV("saved_prefill_work", true);
    return true;
}

bool RetirePrivatePrefix(const std::string& tenant, bool rotate_key, bool active_lease, UniValue& report,
                         std::string& err)
{
    (void)err;
    const std::string owner = CanonicalTenantId(tenant);
    std::lock_guard<std::mutex> lock(g_mu);
    for (auto& kv : g_kv) {
        if (kv.second.owner != owner) continue;
        kv.second.retired = true;
        if (rotate_key) {
            kv.second.payload = UniValue(UniValue::VOBJ);
            kv.second.complete = false;
            kv.second.persist_complete = false;
        }
    }
    if (rotate_key) {
        g_tenant_epoch[owner] = TenantEpoch(owner) + 1;
    }
    report = UniValue(UniValue::VOBJ);
    report.pushKV("new_access", false);
    report.pushKV("active_draining", active_lease);
    report.pushKV("active_drained", !active_lease);
    report.pushKV("persistence", rotate_key ? "key_retired" : "deleted");
    report.pushKV("secure_erase_guaranteed", rotate_key);
    report.pushKV("best_effort_ssd_delete", !rotate_key);
    report.pushKV("automatic_spend_atoms", 0);
    return true;
}

UniValue PrivatePrefixTelemetry(const std::string& tenant)
{
    (void)tenant;
    UniValue o(UniValue::VOBJ);
    o.pushKV("tenant_scoped", true);
    o.pushKV("public_announce", false);
    o.pushKV("public_discovery", false);
    o.pushKV("lmcache_remote", false);
    o.pushKV("controller_telemetry", false);
    o.pushKV("analytics_sink", false);
    o.pushKV("automatic_spend_atoms", 0);
    return o;
}

void SimulatePrivatePrefixRestart()
{
    std::lock_guard<std::mutex> lock(g_mu);
    for (auto it = g_kv.begin(); it != g_kv.end();) {
        if (!it->second.complete || !it->second.persist_complete) {
            it = g_kv.erase(it);
        } else {
            ++it;
        }
    }
}

bool AdmitPrefetchHint(const UniValue& hint, const LocalCapabilityGrant& grant, HostResourceBroker& broker,
                       UniValue& job, std::string& err_code, std::string& err)
{
    job = UniValue(UniValue::VOBJ);
    job.pushKV("automatic_spend_atoms", 0);
    if (HintHasPrivateTranscript(hint)) {
        return Fail(err_code, err, "PRIVACY", "prefetch cannot ingest agent transcript");
    }
    const int64_t now_ms = FieldI64(hint, "now_ms", 0);
    if (!GrantAllows(grant, "PREFETCH", now_ms, err_code, err)) return false;
    if (RejectPaidPath(hint, err_code, err)) return false;
    if (grant.json.isObject() && RejectPaidPath(grant.json, err_code, err)) return false;

    const bool demand = IsDemandHint(hint);
    const std::string recipe = RecipeOf(hint);
    const std::string actor = hint.exists("actor") && hint["actor"].isStr() ? hint["actor"].get_str() : "local";
    const std::string tier = hint.exists("desired_tier") && hint["desired_tier"].isStr() ?
                                 hint["desired_tier"].get_str() :
                                 "HOST_PAGEABLE";
    const uint64_t bytes = hint.exists("bytes") ? FieldU64(hint, "bytes", 1) :
                           (hint.exists("max_speculative_bytes") ? FieldU64(hint, "max_speculative_bytes", 1) : 1);
    const uint64_t host = bytes;
    const uint64_t pinned = FieldU64(hint, "pinned_bytes", 0);
    const uint64_t device = FieldU64(hint, "device_bytes", 0);
    int64_t expires_at_ms = FieldI64(hint, "expires_at_ms", 0);
    if (expires_at_ms == 0) expires_at_ms = FieldI64(hint, "deadline_ms", 0);
    const bool dispatch_now = Truthy(hint, "dispatch") || Truthy(hint, "dispatched");
    const bool fence = Truthy(hint, "lease_active") || Truthy(hint, "fence");
    const int64_t min_residency_ms = FieldI64(hint, "min_residency_ms", 1000);
    const uint64_t spec_cap = SpeculativeCap(hint, grant);
    uint64_t host_cap = grant.host_bytes;
    if (hint.exists("host_physical_bytes")) host_cap = FieldU64(hint, "host_physical_bytes", host_cap);

    if (expires_at_ms > 0 && now_ms > expires_at_ms) {
        return Fail(err_code, err, "DEADLINE_UNACHIEVABLE", "hint expired before begin");
    }

    std::lock_guard<std::mutex> lock(g_mu);

    if (!demand) {
        const std::string last = g_pf.last_recipe[&broker];
        const int64_t last_ms = g_pf.last_admit_ms[&broker];
        if (!last.empty() && last != recipe && now_ms > 0 && last_ms > 0 &&
            (now_ms - last_ms) < min_residency_ms && host + FieldU64(hint, "peer_resident_bytes", 0) > 0) {
            uint64_t used_host = 0;
            for (const auto& j : g_pf.jobs) {
                if (j.broker == &broker && !j.cancelled && !j.finished && j.reserved) used_host += j.host;
            }
            if (host_cap && used_host + host > host_cap) {
                g_pf.thrash_rejects += 1;
                return Fail(err_code, err, "BUDGET_EXCEEDED", "hysteresis: refuse speculative swap");
            }
        }
        if (host_cap) {
            uint64_t used_host = 0;
            for (const auto& j : g_pf.jobs) {
                if (j.broker == &broker && !j.cancelled && !j.finished && j.reserved) used_host += j.host;
            }
            if (used_host + host > host_cap) {
                g_pf.thrash_rejects += 1;
                return Fail(err_code, err, "BUDGET_EXCEEDED", "speculative will not evict resident generations");
            }
        }
        if (broker.PrefetchJobs() >= PREFETCH_JOB_MAX) {
            return Fail(err_code, err, "BUDGET_EXCEEDED", "prefetch jobs");
        }
        uint64_t& used = g_pf.speculative_used[&broker];
        const uint64_t add = host + device;
        if (spec_cap && used + add > spec_cap) {
            return Fail(err_code, err, "BUDGET_EXCEEDED", "speculative budget");
        }
    } else {
        uint64_t used_host = 0;
        for (const auto& j : g_pf.jobs) {
            if (j.broker == &broker && !j.cancelled && !j.finished && j.reserved) used_host += j.host;
        }
        if (host_cap && used_host + host > host_cap) {
            PreemptQueuedSpeculative(broker, host);
        }
        if (broker.PrefetchJobs() >= PREFETCH_JOB_MAX) {
            PreemptQueuedSpeculative(broker, 0);
        }
    }

    std::string perr;
    if (!demand) {
        if (!broker.AdmitPrefetch(perr)) {
            return Fail(err_code, err, "BUDGET_EXCEEDED", perr);
        }
        if (!broker.Reserve(host, pinned, device, /*speculative=*/true, perr)) {
            broker.FinishPrefetch();
            return Fail(err_code, err, "BUDGET_EXCEEDED", perr);
        }
        g_pf.speculative_used[&broker] += host + device;
    } else {
        if (!broker.Reserve(host, pinned, device, /*speculative=*/false, perr)) {
            PreemptQueuedSpeculative(broker, host);
            if (!broker.Reserve(host, pinned, device, /*speculative=*/false, perr)) {
                return Fail(err_code, err, "MEMORY_RESERVATION_FAILED", perr);
            }
        }
    }

    PrefetchJob rec;
    rec.job_id = GenerationHex(NewGeneration());
    rec.broker = &broker;
    rec.demand = demand;
    rec.dispatched = dispatch_now;
    rec.fence = fence || dispatch_now;
    rec.slot = !demand;
    rec.reserved = true;
    rec.host = host;
    rec.pinned = pinned;
    rec.device = device;
    rec.expires_at_ms = expires_at_ms;
    rec.actor = actor;
    rec.recipe = recipe;
    rec.desired_tier = tier;
    g_pf.jobs.push_back(rec);
    g_pf.admitted += 1;
    g_pf.last_recipe[&broker] = recipe;
    g_pf.last_admit_ms[&broker] = now_ms;

    job.pushKV("job_id", rec.job_id);
    job.pushKV("priority", demand ? "DEMAND" : "SPECULATIVE");
    job.pushKV("state", rec.dispatched ? "DISPATCHED" : "QUEUED");
    job.pushKV("dispatched", rec.dispatched);
    job.pushKV("recipe_id", recipe);
    job.pushKV("actor", actor);
    job.pushKV("desired_tier", tier);
    job.pushKV("bytes", std::to_string(host));
    job.pushKV("prefetch_jobs", broker.PrefetchJobs());
    job.pushKV("speculative", !demand);

    UniValue transitions(UniValue::VARR);
    if (hint.exists("component_role") && hint["component_role"].isStr() &&
        hint["component_role"].get_str() == "ADAPTER") {
        UniValue t(UniValue::VOBJ);
        t.pushKV("component", "adapter");
        t.pushKV("from", "LOCAL_FILE");
        t.pushKV("to", tier);
        transitions.push_back(t);
    }
    job.pushKV("tier_transitions", transitions);
    const std::string base_tier = hint.exists("base_resident_tier") && hint["base_resident_tier"].isStr() ?
                                      hint["base_resident_tier"].get_str() :
                                      "DEVICE";
    job.pushKV("base_tier", base_tier);
    job.pushKV("base_promoted", false);
    return true;
}

bool AcceptExecutableCache(const UniValue& cache, bool trusted_builder, const Digest48& model_author_sig,
                           std::string& err_code, std::string& err)
{
    (void)model_author_sig;
    if (RejectPaidPath(cache, err_code, err)) return false;
    if (HasGraphPointers(cache)) {
        return Fail(err_code, err, "GRAPH_POINTER_NOT_PORTABLE",
                    "compiled binary cache is not a live graph snapshot");
    }
    if (UnsafeCacheFormat(cache)) {
        return Fail(err_code, err, "EXECUTABLE_CACHE_REJECTED", "unknown or unsafe cache format");
    }
    if (Truthy(cache, "corrupt")) {
        return Fail(err_code, err, "EXECUTABLE_CACHE_REJECTED", "corrupt runtime artifact");
    }
    if (cache.exists("canonical_checkpoint_hash") && cache.exists("representation_digest48") &&
        cache["canonical_checkpoint_hash"].isStr() && cache["representation_digest48"].isStr()) {
        if (cache.exists("tensor_digest48") && cache["tensor_digest48"].isStr() &&
            cache["tensor_digest48"].get_str() != cache["representation_digest48"].get_str()) {
            return Fail(err_code, err, "REPRESENTATION_MISMATCH",
                        "canonical checkpoint hash does not prove transformed tensors");
        }
        if (Truthy(cache, "wrong_repack") ||
            (cache.exists("labeled_as_canonical") && cache["labeled_as_canonical"].isTrue() &&
             cache.exists("tensor_digest48") &&
             cache["tensor_digest48"].get_str() != cache["canonical_checkpoint_hash"].get_str())) {
            return Fail(err_code, err, "REPRESENTATION_MISMATCH",
                        "canonical checkpoint hash does not prove transformed tensors");
        }
    }
    if (cache.exists("required") && cache["required"].isObject()) {
        Digest48 got{}, need{};
        std::string ferr;
        if (!ExecutableCacheFingerprint(cache, got, ferr) ||
            !ExecutableCacheFingerprint(cache["required"], need, ferr) || got != need) {
            return Fail(err_code, err, "CACHE_MISS", "compiler/runtime/dtype/shape/model digest mismatch");
        }
    }
    if (cache.exists("host_fingerprint") && cache["host_fingerprint"].isObject()) {
        Digest48 got{}, need{};
        std::string ferr;
        if (!ExecutableCacheFingerprint(cache, got, ferr) ||
            !ExecutableCacheFingerprint(cache["host_fingerprint"], need, ferr) || got != need) {
            return Fail(err_code, err, "CACHE_MISS", "compiler/runtime/dtype/shape/model digest mismatch");
        }
    }
    if (!trusted_builder && (ClaimsModelAuthorSignature(cache) || !IsLocalBuild(cache))) {
        return Fail(err_code, err, "SOFTWARE_TRUST_REQUIRED",
                    "model author signature does not authorize executable cache");
    }
    err_code.clear();
    err.clear();
    return true;
}

bool PrivatePrefixKey(const std::string& tenant, const UniValue& config_fingerprint, const std::string& token_prefix,
                      Digest48& out, std::string& err)
{
    const std::string owner = CanonicalTenantId(tenant);
    if (!TenantIdUsable(owner)) {
        err = "tenant isolation";
        return false;
    }
    uint64_t epoch = 0;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        epoch = TenantEpoch(owner);
    }
    UniValue o(UniValue::VOBJ);
    o.pushKV("tenant", owner);
    o.pushKV("config", config_fingerprint);
    o.pushKV("token_prefix", token_prefix);
    o.pushKV("epoch", std::to_string(epoch));
    return CapabilityObjectIdJson("BTX/PrivatePrefix/v1", o, out, err);
}

bool PrefixVisibleToTenant(const std::string& owner_tenant, const std::string& requester)
{
    if (!TenantIdUsable(owner_tenant) || !TenantIdUsable(requester)) return false;
    return CanonicalTenantId(owner_tenant) == CanonicalTenantId(requester);
}

} // namespace modelnet
