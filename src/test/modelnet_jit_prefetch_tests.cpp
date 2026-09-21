// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Native unit coverage for BTX-SPEC-0348-CAPABILITY-01 Worker H:
//   JIT-PREFETCH-01..07  JIT-CACHE-01..07  JIT-KV-01..07
// Isolated HostResourceBroker; no production btxd, helper, or wallet.

#include <modelnet/capability.h>
#include <test/util/setup_common.h>
#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace modelnet {
void ResetCapabilityPrefetchForTests();
bool DispatchPrefetchJob(const std::string& job_id, HostResourceBroker& broker, std::string& err_code, std::string& err);
bool ExpirePrefetchHints(int64_t now_ms, HostResourceBroker& broker, UniValue& report);
bool FinishPrefetchJob(const std::string& job_id, HostResourceBroker& broker, std::string& err_code, std::string& err);
bool RecordPrefetchOutcome(const std::string& job_id, bool used, uint64_t avoided_latency_ms, uint64_t wasted_bytes);
UniValue PrefetchMetricsJson();
bool ExecutableCacheFingerprint(const UniValue& cache, Digest48& out, std::string& err);
bool CommitExecutableCache(const UniValue& cache, bool crash_before_promote, UniValue& visible, std::string& err_code,
                           std::string& err);
bool LookupExecutableCache(const UniValue& query, UniValue& hit, std::string& err_code, std::string& err);
bool LocalCompileFallback(const UniValue& rejected, bool authorized, UniValue& result, std::string& err_code,
                          std::string& err);
bool MeasureWarmCacheBenefit(const UniValue& cold, const UniValue& warm, UniValue& report, std::string& err_code,
                             std::string& err);
bool PutPrivatePrefix(const std::string& tenant, const UniValue& config_fingerprint, const std::string& token_prefix,
                      const UniValue& state, std::string& err_code, std::string& err);
bool GetPrivatePrefix(const std::string& requester, const std::string& owner_tenant, const UniValue& config_fingerprint,
                      const std::string& token_prefix, UniValue& state, std::string& err_code, std::string& err);
bool RetirePrivatePrefix(const std::string& tenant, bool rotate_key, bool active_lease, UniValue& report,
                         std::string& err);
UniValue PrivatePrefixTelemetry(const std::string& tenant);
void SimulatePrivatePrefixRestart();
} // namespace modelnet

BOOST_FIXTURE_TEST_SUITE(modelnet_jit_prefetch_tests, BasicTestingSetup)

using namespace modelnet;

namespace {

LocalCapabilityGrant MakeGrant(uint64_t host_bytes = 1 << 20)
{
    LocalCapabilityGrant g;
    g.caller = "local";
    g.expires_at_ms = 0;
    g.revoked = false;
    g.host_bytes = host_bytes;
    g.json = UniValue(UniValue::VOBJ);
    UniValue mem(UniValue::VOBJ);
    mem.pushKV("host_physical_bytes", std::to_string(host_bytes));
    mem.pushKV("speculative_bytes", std::to_string(host_bytes / 2));
    g.json.pushKV("memory", mem);
    g.json.pushKV("automatic_spend_atoms", 0);
    return g;
}

HostResourceBroker MakeBroker(uint64_t host, uint64_t speculative)
{
    HostResourceBroker b;
    MemoryLimits lim;
    lim.host_physical_bytes = host;
    lim.host_pinned_bytes = host;
    lim.device_bytes = host;
    lim.speculative_bytes = speculative;
    std::string err;
    BOOST_REQUIRE(b.Configure(lim, err));
    return b;
}

UniValue SpecHint(const std::string& recipe, uint64_t bytes, const std::string& actor = "agent-a")
{
    UniValue h(UniValue::VOBJ);
    UniValue ids(UniValue::VARR);
    ids.push_back(recipe);
    h.pushKV("recipe_ids", ids);
    h.pushKV("priority", "SPECULATIVE");
    h.pushKV("bytes", std::to_string(bytes));
    h.pushKV("actor", actor);
    h.pushKV("speculative_pool_bytes", std::to_string(uint64_t{1} << 20));
    h.pushKV("host_physical_bytes", std::to_string(uint64_t{1} << 20));
    h.pushKV("automatic_spend_atoms", 0);
    h.pushKV("desired_tier", "HOST_PAGEABLE");
    return h;
}

UniValue DemandHint(const std::string& recipe, uint64_t bytes)
{
    UniValue h = SpecHint(recipe, bytes, "foreground");
    h.pushKV("priority", "DEMAND");
    h.pushKV("demand", true);
    return h;
}

UniValue Shape(int64_t a, int64_t b)
{
    UniValue s(UniValue::VARR);
    s.push_back(a);
    s.push_back(b);
    return s;
}

UniValue MakeCache()
{
    UniValue c(UniValue::VOBJ);
    c.pushKV("format", "cubin");
    c.pushKV("compiler", "nvcc-12.4");
    c.pushKV("runtime_id", "llama.cpp");
    c.pushKV("dtype", "F16");
    c.pushKV("shape", Shape(1, 64));
    c.pushKV("model_digest", std::string(96, 'a'));
    c.pushKV("friendly_name", "legal-assistant");
    c.pushKV("verification_method", "TRUSTED_BUILD_ATTESTATION");
    return c;
}

UniValue RequiredFp(const UniValue& cache)
{
    UniValue r(UniValue::VOBJ);
    r.pushKV("compiler", cache["compiler"]);
    r.pushKV("runtime_id", cache["runtime_id"]);
    r.pushKV("dtype", cache["dtype"]);
    r.pushKV("shape", cache["shape"]);
    r.pushKV("model_digest", cache["model_digest"]);
    return r;
}

UniValue KvConfig(const std::string& adapters, const std::string& tokenizer, const std::string& rope)
{
    UniValue c(UniValue::VOBJ);
    c.pushKV("adapters", adapters);
    c.pushKV("adapter_order", adapters);
    c.pushKV("tokenizer", tokenizer);
    c.pushKV("rope", rope);
    c.pushKV("chat_template", "chatml");
    return c;
}

UniValue CompleteKv()
{
    UniValue s(UniValue::VOBJ);
    s.pushKV("complete_layers", 2);
    s.pushKV("expected_layers", 2);
    s.pushKV("persist_complete", true);
    s.pushKV("output_digest", std::string(96, 'b'));
    s.pushKV("saved_prefill_work", true);
    s.pushKV("prefill_tokens", 64);
    return s;
}

Digest48 PublisherSig()
{
    Digest48 s{};
    s.data[0] = 0x42;
    s.data[1] = 0x11;
    return s;
}

} // namespace

BOOST_AUTO_TEST_CASE(JIT_PREFETCH_01)
{
    // JIT-PREFETCH-01 — Demand preemption
    ResetCapabilityPrefetchForTests();
    BOOST_CHECK_EQUAL(PREFETCH_JOB_MAX, 2);
    auto broker = MakeBroker(/*host=*/500, /*speculative=*/500);
    auto grant = MakeGrant(500);
    std::string ec, err;
    UniValue job;

    UniValue h1 = SpecHint("recipe-a", 200, "agent-a");
    h1.pushKV("host_physical_bytes", 500);
    h1.pushKV("speculative_pool_bytes", 500);
    BOOST_REQUIRE(AdmitPrefetchHint(h1, grant, broker, job, ec, err));
    BOOST_CHECK_EQUAL(job["priority"].get_str(), "SPECULATIVE");
    BOOST_CHECK(job["dispatched"].isFalse());
    const std::string spec_a = job["job_id"].get_str();

    UniValue h2 = SpecHint("recipe-b", 200, "agent-b");
    h2.pushKV("host_physical_bytes", 500);
    h2.pushKV("speculative_pool_bytes", 500);
    BOOST_REQUIRE(AdmitPrefetchHint(h2, grant, broker, job, ec, err));
    BOOST_CHECK_EQUAL(broker.PrefetchJobs(), 2);
    const std::string spec_b = job["job_id"].get_str();

    UniValue demand = DemandHint("recipe-urgent", 200);
    demand.pushKV("host_physical_bytes", 500);
    BOOST_REQUIRE(AdmitPrefetchHint(demand, grant, broker, job, ec, err));
    BOOST_CHECK_EQUAL(job["priority"].get_str(), "DEMAND");
    BOOST_CHECK(job["speculative"].isFalse());
    BOOST_CHECK_EQUAL(job["recipe_id"].get_str(), "recipe-urgent");
    BOOST_CHECK(job["automatic_spend_atoms"].getInt<int>() == 0);
    BOOST_CHECK(broker.PrefetchJobs() < PREFETCH_JOB_MAX);
    BOOST_CHECK_EQUAL(broker.PrefetchJobs(), 1);
    {
        std::string dec, derr;
        int cancelled = 0;
        if (!DispatchPrefetchJob(spec_a, broker, dec, derr)) {
            ++cancelled;
            BOOST_CHECK_EQUAL(dec, "HINT_EXPIRED");
        }
        if (!DispatchPrefetchJob(spec_b, broker, dec, derr)) {
            ++cancelled;
            BOOST_CHECK_EQUAL(dec, "HINT_EXPIRED");
        }
        BOOST_CHECK(cancelled >= 1);
    }

    ResetCapabilityPrefetchForTests();
    broker = MakeBroker(500, 500);
    UniValue fenced = SpecHint("recipe-hot", 200, "agent-a");
    fenced.pushKV("dispatch", true);
    fenced.pushKV("lease_active", true);
    BOOST_REQUIRE(AdmitPrefetchHint(fenced, grant, broker, job, ec, err));
    BOOST_CHECK_EQUAL(broker.PrefetchJobs(), 1);
    const std::string fenced_id = job["job_id"].get_str();
    UniValue queued = SpecHint("recipe-cold", 200, "agent-b");
    BOOST_REQUIRE(AdmitPrefetchHint(queued, grant, broker, job, ec, err));
    const std::string queued_id = job["job_id"].get_str();
    UniValue d2 = DemandHint("recipe-fg", 150);
    BOOST_REQUIRE(AdmitPrefetchHint(d2, grant, broker, job, ec, err));
    BOOST_CHECK_EQUAL(job["priority"].get_str(), "DEMAND");
    BOOST_CHECK(job["speculative"].isFalse());
    BOOST_CHECK_EQUAL(broker.PrefetchJobs(), 1);
    BOOST_REQUIRE(DispatchPrefetchJob(fenced_id, broker, ec, err));
    BOOST_CHECK(!DispatchPrefetchJob(queued_id, broker, ec, err));
    BOOST_CHECK_EQUAL(ec, "HINT_EXPIRED");

    BOOST_TEST_CONTEXT("demand pre-empts remaining speculative bytes") {
        ResetCapabilityPrefetchForTests();
        broker = MakeBroker(500, 500);
        UniValue s1 = SpecHint("recipe-a", 200, "agent-a");
        s1.pushKV("host_physical_bytes", 500);
        s1.pushKV("speculative_pool_bytes", 500);
        BOOST_REQUIRE(AdmitPrefetchHint(s1, grant, broker, job, ec, err));
        UniValue s2 = SpecHint("recipe-b", 200, "agent-b");
        s2.pushKV("host_physical_bytes", 500);
        s2.pushKV("speculative_pool_bytes", 500);
        BOOST_REQUIRE(AdmitPrefetchHint(s2, grant, broker, job, ec, err));
        BOOST_CHECK_EQUAL(broker.PrefetchJobs(), 2);
        UniValue big = DemandHint("recipe-fg-large", 400);
        big.pushKV("host_physical_bytes", 500);
        BOOST_REQUIRE(AdmitPrefetchHint(big, grant, broker, job, ec, err));
        BOOST_CHECK_EQUAL(job["priority"].get_str(), "DEMAND");
        BOOST_CHECK_EQUAL(job["recipe_id"].get_str(), "recipe-fg-large");
        BOOST_CHECK_EQUAL(broker.PrefetchJobs(), 0);
    }
}

BOOST_AUTO_TEST_CASE(JIT_PREFETCH_02)
{
    // JIT-PREFETCH-02 — Speculation ceiling
    ResetCapabilityPrefetchForTests();
    auto broker = MakeBroker(10 * 1024, 64);
    auto grant = MakeGrant(10 * 1024);
    std::string ec, err;
    int ok = 0;
    int denied = 0;
    for (int i = 0; i < 200; ++i) {
        UniValue h = SpecHint("recipe-" + std::to_string(i % 3), /*bytes=*/1, i % 2 ? "actor-a" : "actor-b");
        UniValue job;
        if (AdmitPrefetchHint(h, grant, broker, job, ec, err)) {
            ++ok;
        } else {
            ++denied;
            BOOST_CHECK_EQUAL(ec, "BUDGET_EXCEEDED");
        }
    }
    BOOST_CHECK_EQUAL(ok, PREFETCH_JOB_MAX);
    BOOST_CHECK_EQUAL(denied, 200 - PREFETCH_JOB_MAX);
    BOOST_CHECK_EQUAL(broker.PrefetchJobs(), PREFETCH_JOB_MAX);
}

BOOST_AUTO_TEST_CASE(JIT_PREFETCH_03)
{
    // JIT-PREFETCH-03 — Hint expiry
    ResetCapabilityPrefetchForTests();
    auto broker = MakeBroker(1000, 500);
    auto grant = MakeGrant(1000);
    std::string ec, err;
    UniValue job;

    UniValue queued = SpecHint("recipe-q", 10);
    queued.pushKV("expires_at_ms", 10);
    queued.pushKV("now_ms", 0);
    BOOST_REQUIRE(AdmitPrefetchHint(queued, grant, broker, job, ec, err));
    BOOST_CHECK_EQUAL(broker.PrefetchJobs(), 1);
    UniValue report;
    BOOST_REQUIRE(ExpirePrefetchHints(20, broker, report));
    BOOST_CHECK_EQUAL(report["cancelled_queued"].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(broker.PrefetchJobs(), 0);

    UniValue already = SpecHint("recipe-late", 10);
    already.pushKV("expires_at_ms", 5);
    already.pushKV("now_ms", 9);
    BOOST_CHECK(!AdmitPrefetchHint(already, grant, broker, job, ec, err));
    BOOST_CHECK_EQUAL(ec, "DEADLINE_UNACHIEVABLE");
    BOOST_CHECK_EQUAL(broker.PrefetchJobs(), 0);

    UniValue run = SpecHint("recipe-run", 10);
    run.pushKV("expires_at_ms", 10);
    run.pushKV("now_ms", 0);
    BOOST_REQUIRE(AdmitPrefetchHint(run, grant, broker, job, ec, err));
    const std::string running = job["job_id"].get_str();
    BOOST_REQUIRE(DispatchPrefetchJob(running, broker, ec, err));
    BOOST_CHECK_EQUAL(broker.PrefetchJobs(), 1);
    BOOST_REQUIRE(ExpirePrefetchHints(50, broker, report));
    BOOST_CHECK_EQUAL(report["cancelled_queued"].getInt<int>(), 0);
    BOOST_CHECK_EQUAL(report["dispatched_still_charged"].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(broker.PrefetchJobs(), 1);
    BOOST_REQUIRE(FinishPrefetchJob(running, broker, ec, err));
    BOOST_CHECK_EQUAL(broker.PrefetchJobs(), 0);
}

BOOST_AUTO_TEST_CASE(JIT_PREFETCH_04)
{
    // JIT-PREFETCH-04 — Useful hit metric
    ResetCapabilityPrefetchForTests();
    auto broker = MakeBroker(1000, 500);
    auto grant = MakeGrant(1000);
    std::string ec, err;
    UniValue ja, jb;
    BOOST_REQUIRE(AdmitPrefetchHint(SpecHint("used-recipe", 40), grant, broker, ja, ec, err));
    BOOST_REQUIRE(AdmitPrefetchHint(SpecHint("abandoned-recipe", 80), grant, broker, jb, ec, err));
    BOOST_REQUIRE(RecordPrefetchOutcome(ja["job_id"].get_str(), true, /*avoided=*/25, 0));
    BOOST_REQUIRE(RecordPrefetchOutcome(jb["job_id"].get_str(), false, 0, 80));
    const UniValue m = PrefetchMetricsJson();
    BOOST_CHECK_EQUAL(m["hits"].get_str(), "1");
    BOOST_CHECK_EQUAL(m["abandoned"].get_str(), "1");
    BOOST_CHECK_EQUAL(m["wasted_bytes"].get_str(), "80");
    BOOST_CHECK_EQUAL(m["avoided_latency_ms"].get_str(), "25");
    BOOST_CHECK(m["hits"].get_str() != m["admitted"].get_str());
}

BOOST_AUTO_TEST_CASE(JIT_PREFETCH_05)
{
    // JIT-PREFETCH-05 — No thrashing
    ResetCapabilityPrefetchForTests();
    auto broker = MakeBroker(100, 100);
    auto grant = MakeGrant(100);
    std::string ec, err;
    UniValue job;
    UniValue a = SpecHint("model-a", 80, "predictor");
    a.pushKV("host_physical_bytes", 100);
    a.pushKV("speculative_pool_bytes", 100);
    a.pushKV("dispatch", true);
    a.pushKV("now_ms", 1000);
    BOOST_REQUIRE(AdmitPrefetchHint(a, grant, broker, job, ec, err));

    for (int i = 0; i < 40; ++i) {
        UniValue b = SpecHint(i % 2 ? "model-b" : "model-a", 80, "predictor");
        b.pushKV("host_physical_bytes", 100);
        b.pushKV("speculative_pool_bytes", 100);
        b.pushKV("now_ms", 1000 + i);
        b.pushKV("min_residency_ms", 5000);
        BOOST_CHECK(!AdmitPrefetchHint(b, grant, broker, job, ec, err));
        BOOST_CHECK_EQUAL(ec, "BUDGET_EXCEEDED");
    }
    const UniValue m = PrefetchMetricsJson();
    BOOST_CHECK_EQUAL(m["speculative_evictions"].get_str(), "0");
    BOOST_CHECK(std::stoull(m["thrash_rejects"].get_str()) >= 1);

    UniValue d = DemandHint("foreground-adapter", 10);
    d.pushKV("host_physical_bytes", 100);
    BOOST_REQUIRE(AdmitPrefetchHint(d, grant, broker, job, ec, err));
    BOOST_CHECK_EQUAL(job["priority"].get_str(), "DEMAND");
}

BOOST_AUTO_TEST_CASE(JIT_PREFETCH_06)
{
    // JIT-PREFETCH-06 — Private intent
    ResetCapabilityPrefetchForTests();
    auto broker = MakeBroker(1000, 100);
    auto grant = MakeGrant(1000);
    std::string ec, err;
    UniValue job;
    UniValue dirty = SpecHint("recipe-x", 8);
    dirty.pushKV("prompt_transcript", "secret user plan");
    BOOST_CHECK(!AdmitPrefetchHint(dirty, grant, broker, job, ec, err));
    BOOST_CHECK_EQUAL(ec, "PRIVACY");
    BOOST_CHECK(!job.exists("prompt_transcript"));
    BOOST_CHECK_EQUAL(broker.PrefetchJobs(), 0);

    UniValue scratch = SpecHint("recipe-x", 8);
    scratch.pushKV("agent_scratchpad", "chain-of-thought");
    BOOST_CHECK(!AdmitPrefetchHint(scratch, grant, broker, job, ec, err));
    BOOST_CHECK_EQUAL(ec, "PRIVACY");

    UniValue plan = SpecHint("recipe-x", 8);
    plan.pushKV("planning_context", "secret plan");
    BOOST_CHECK(!AdmitPrefetchHint(plan, grant, broker, job, ec, err));
    BOOST_CHECK_EQUAL(ec, "PRIVACY");
    BOOST_CHECK_EQUAL(broker.PrefetchJobs(), 0);

    UniValue clean = SpecHint("recipe-x", 8);
    BOOST_REQUIRE(AdmitPrefetchHint(clean, grant, broker, job, ec, err));
    const std::string dumped = job.write();
    BOOST_CHECK(dumped.find("prompt") == std::string::npos);
    BOOST_CHECK(dumped.find("transcript") == std::string::npos);
    BOOST_CHECK_EQUAL(job["automatic_spend_atoms"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_CASE(JIT_PREFETCH_07)
{
    // JIT-PREFETCH-07 — Tier-specific prefetch
    ResetCapabilityPrefetchForTests();
    auto broker = MakeBroker(1000, 100);
    auto grant = MakeGrant(1000);
    std::string ec, err;
    UniValue job;
    UniValue h = SpecHint("adapter-only", 8);
    h.pushKV("desired_tier", "HOST_PAGEABLE");
    h.pushKV("component_role", "ADAPTER");
    h.pushKV("base_resident_tier", "DEVICE");
    BOOST_REQUIRE(AdmitPrefetchHint(h, grant, broker, job, ec, err));
    BOOST_CHECK_EQUAL(job["desired_tier"].get_str(), "HOST_PAGEABLE");
    BOOST_CHECK_EQUAL(job["base_tier"].get_str(), "DEVICE");
    BOOST_CHECK(job["base_promoted"].isFalse());
    BOOST_REQUIRE(job["tier_transitions"].isArray());
    BOOST_CHECK_EQUAL(job["tier_transitions"].size(), 1);
    BOOST_CHECK_EQUAL(job["tier_transitions"][0]["component"].get_str(), "adapter");
    BOOST_CHECK_EQUAL(job["tier_transitions"][0]["to"].get_str(), "HOST_PAGEABLE");
    std::string pec, perr;
    BOOST_CHECK(PlaceInTier(PlacementTier::HOST_PAGEABLE, PlacementTier::HOST_PAGEABLE, pec, perr));
}

BOOST_AUTO_TEST_CASE(JIT_CACHE_01)
{
    // JIT-CACHE-01 — Cache fingerprint
    ResetCapabilityPrefetchForTests();
    std::string ec, err;
    UniValue cache = MakeCache();
    const UniValue req = RequiredFp(cache);
    cache.pushKV("required", req);
    BOOST_REQUIRE(AcceptExecutableCache(cache, /*trusted_builder=*/true, PublisherSig(), ec, err));

    Digest48 fp1{}, fp2{};
    BOOST_REQUIRE(ExecutableCacheFingerprint(cache, fp1, err));
    cache.pushKV("friendly_name", "totally-different-label");
    BOOST_REQUIRE(ExecutableCacheFingerprint(cache, fp2, err));
    BOOST_CHECK(fp1 == fp2);

    auto miss = [&](const char* field, const UniValue& val) {
        UniValue c = MakeCache();
        c.pushKV(field, val);
        c.pushKV("friendly_name", "legal-assistant");
        c.pushKV("required", req);
        std::string e2, m2;
        BOOST_CHECK(!AcceptExecutableCache(c, true, PublisherSig(), e2, m2));
        BOOST_CHECK_EQUAL(e2, "CACHE_MISS");
    };
    miss("compiler", UniValue("clang-other"));
    miss("runtime_id", UniValue("vllm"));
    miss("dtype", UniValue("F32"));
    miss("shape", Shape(1, 128));
    miss("model_digest", UniValue(std::string(96, 'c')));
}

BOOST_AUTO_TEST_CASE(JIT_CACHE_02)
{
    // JIT-CACHE-02 — Untrusted executable cache
    ResetCapabilityPrefetchForTests();
    std::string ec, err;
    UniValue cache = MakeCache();
    cache.pushKV("required", RequiredFp(cache));
    const Digest48 pub = PublisherSig();
    BOOST_CHECK(!AcceptExecutableCache(cache, /*trusted_builder=*/false, pub, ec, err));
    BOOST_CHECK_EQUAL(ec, "SOFTWARE_TRUST_REQUIRED");
    BOOST_REQUIRE(AcceptExecutableCache(cache, /*trusted_builder=*/true, pub, ec, err));

    BOOST_TEST_CONTEXT("MODEL_AUTHOR_SIGNATURE SOFTWARE_TRUST_REQUIRED") {
        UniValue author = MakeCache();
        author.pushKV("verification_method", "MODEL_AUTHOR_SIGNATURE");
        author.pushKV("required", RequiredFp(author));
        BOOST_CHECK(!AcceptExecutableCache(author, /*trusted_builder=*/false, pub, ec, err));
        BOOST_CHECK_EQUAL(ec, "SOFTWARE_TRUST_REQUIRED");
        BOOST_CHECK(!AcceptExecutableCache(author, false, Digest48{}, ec, err));
        BOOST_CHECK_EQUAL(ec, "SOFTWARE_TRUST_REQUIRED");
        UniValue launder = author;
        launder.pushKV("source", "local_compile");
        BOOST_CHECK(!AcceptExecutableCache(launder, false, pub, ec, err));
        BOOST_CHECK_EQUAL(ec, "SOFTWARE_TRUST_REQUIRED");
        BOOST_REQUIRE(AcceptExecutableCache(author, /*trusted_builder=*/true, pub, ec, err));
    }

    UniValue pickle = MakeCache();
    pickle.pushKV("format", "pickle");
    BOOST_CHECK(!AcceptExecutableCache(pickle, true, pub, ec, err));
    BOOST_CHECK_EQUAL(ec, "EXECUTABLE_CACHE_REJECTED");
}

BOOST_AUTO_TEST_CASE(JIT_CACHE_03)
{
    // JIT-CACHE-03 — Local compile fallback
    ResetCapabilityPrefetchForTests();
    std::string ec, err;
    UniValue cache = MakeCache();
    cache.pushKV("corrupt", true);
    cache.pushKV("required", RequiredFp(MakeCache()));
    BOOST_CHECK(!AcceptExecutableCache(cache, true, PublisherSig(), ec, err));
    BOOST_CHECK_EQUAL(ec, "EXECUTABLE_CACHE_REJECTED");

    UniValue compiled;
    BOOST_REQUIRE(LocalCompileFallback(cache, /*authorized=*/true, compiled, ec, err));
    BOOST_CHECK(compiled["compiled_locally"].isTrue());
    BOOST_CHECK(compiled["fetched_arbitrary_code"].isFalse());
    BOOST_CHECK_EQUAL(compiled["source"].get_str(), "local_compile");

    UniValue remote = cache;
    remote.pushKV("remote_code_fetch", true);
    UniValue bad;
    BOOST_CHECK(!LocalCompileFallback(remote, true, bad, ec, err));
    BOOST_CHECK_EQUAL(ec, "EXECUTABLE_CACHE_REJECTED");
    BOOST_CHECK(bad["fetched_arbitrary_code"].isFalse());
}

BOOST_AUTO_TEST_CASE(JIT_CACHE_04)
{
    // JIT-CACHE-04 — Transformed tensor proof
    ResetCapabilityPrefetchForTests();
    std::string ec, err;
    UniValue cache = MakeCache();
    cache.pushKV("canonical_checkpoint_hash", std::string(96, 'a'));
    cache.pushKV("representation_digest48", std::string(96, 'd'));
    cache.pushKV("tensor_digest48", std::string(96, 'e'));
    cache.pushKV("labeled_as_canonical", true);
    cache.pushKV("required", RequiredFp(cache));
    BOOST_CHECK(!AcceptExecutableCache(cache, true, PublisherSig(), ec, err));
    BOOST_CHECK_EQUAL(ec, "REPRESENTATION_MISMATCH");
}

BOOST_AUTO_TEST_CASE(JIT_CACHE_05)
{
    // JIT-CACHE-05 — Graph pointer portability
    ResetCapabilityPrefetchForTests();
    std::string ec, err;
    UniValue cache = MakeCache();
    cache.pushKV("contains_generation_pointers", true);
    cache.pushKV("required", RequiredFp(MakeCache()));
    BOOST_CHECK(!AcceptExecutableCache(cache, true, PublisherSig(), ec, err));
    BOOST_CHECK_EQUAL(ec, "GRAPH_POINTER_NOT_PORTABLE");

    UniValue graph = MakeCache();
    graph.pushKV("format", "cuda_graph");
    BOOST_CHECK(!AcceptExecutableCache(graph, true, PublisherSig(), ec, err));
    BOOST_CHECK_EQUAL(ec, "GRAPH_POINTER_NOT_PORTABLE");
}

BOOST_AUTO_TEST_CASE(JIT_CACHE_06)
{
    // JIT-CACHE-06 — Concurrent builder commit
    ResetCapabilityPrefetchForTests();
    std::string ec, err;
    UniValue cache = MakeCache();
    UniValue vis;
    BOOST_REQUIRE(CommitExecutableCache(cache, /*crash_before_promote=*/true, vis, ec, err));
    BOOST_CHECK(vis["visible"].isFalse());
    BOOST_CHECK(vis["partial"].isTrue());
    UniValue hit;
    BOOST_CHECK(!LookupExecutableCache(cache, hit, ec, err));
    BOOST_CHECK_EQUAL(ec, "CACHE_MISS");
    BOOST_CHECK(hit["hit"].isFalse());

    UniValue vis2;
    BOOST_REQUIRE(CommitExecutableCache(cache, /*crash_before_promote=*/false, vis2, ec, err));
    BOOST_CHECK(vis2["visible"].isTrue());
    BOOST_REQUIRE(LookupExecutableCache(cache, hit, ec, err));
    BOOST_CHECK(hit["hit"].isTrue());

    UniValue crash_later;
    BOOST_REQUIRE(CommitExecutableCache(cache, true, crash_later, ec, err));
    BOOST_REQUIRE(LookupExecutableCache(cache, hit, ec, err));
    BOOST_CHECK(hit["hit"].isTrue());
}

BOOST_AUTO_TEST_CASE(JIT_CACHE_07)
{
    // JIT-CACHE-07 — Measured warm benefit
    ResetCapabilityPrefetchForTests();
    std::string ec, err;
    UniValue cold(UniValue::VOBJ);
    cold.pushKV("layers", 32);
    cold.pushKV("quant", "q4_k");
    cold.pushKV("workload", "prefill-64");
    cold.pushKV("model_digest", std::string(96, 'a'));
    cold.pushKV("output_digest", std::string(96, 'f'));
    cold.pushKV("startup_ms", 400);
    UniValue warm = cold;
    warm.pushKV("startup_ms", 40);
    warm.pushKV("cache_source", "local_cubin");
    UniValue report;
    BOOST_REQUIRE(MeasureWarmCacheBenefit(cold, warm, report, ec, err));
    BOOST_CHECK_EQUAL(report["saved_ms"].get_str(), "360");
    BOOST_CHECK_EQUAL(report["cache_source"].get_str(), "local_cubin");
    BOOST_CHECK(report["correctness_match"].isTrue());
    BOOST_CHECK(report["synthetic_pass"].isFalse());

    UniValue unequal = warm;
    unequal.pushKV("layers", 8);
    BOOST_CHECK(!MeasureWarmCacheBenefit(cold, unequal, report, ec, err));
    BOOST_CHECK_EQUAL(ec, "SYNTHETIC_PASS_FORBIDDEN");
}

BOOST_AUTO_TEST_CASE(JIT_KV_01)
{
    // JIT-KV-01 — Exact prefix hit
    ResetCapabilityPrefetchForTests();
    std::string ec, err;
    const UniValue cfg = KvConfig("lora-a@1.0", "tok-v1", "rope-ntk");
    const std::string prefix = "exact-token-prefix";
    Digest48 k1{}, k2{};
    BOOST_REQUIRE(PrivatePrefixKey("tenant-a", cfg, prefix, k1, err));
    BOOST_REQUIRE(PrivatePrefixKey("tenant-a", cfg, prefix, k2, err));
    BOOST_CHECK(k1 == k2);
    BOOST_REQUIRE(PutPrivatePrefix("tenant-a", cfg, prefix, CompleteKv(), ec, err));
    UniValue got;
    BOOST_REQUIRE(GetPrivatePrefix("tenant-a", "tenant-a", cfg, prefix, got, ec, err));
    BOOST_CHECK_EQUAL(got["output_digest"].get_str(), std::string(96, 'b'));
    BOOST_CHECK(got["saved_prefill_work"].isTrue());
}

BOOST_AUTO_TEST_CASE(JIT_KV_02)
{
    // JIT-KV-02 — Adapter invalidation
    ResetCapabilityPrefetchForTests();
    std::string ec, err;
    const UniValue cfg_a = KvConfig("lora-a@1.0,lora-b@0.5", "tok-v1", "rope-ntk");
    const UniValue cfg_b = KvConfig("lora-b@0.5,lora-a@1.0", "tok-v1", "rope-ntk");
    Digest48 ka{}, kb{};
    BOOST_REQUIRE(PrivatePrefixKey("tenant-a", cfg_a, "same-text", ka, err));
    BOOST_REQUIRE(PrivatePrefixKey("tenant-a", cfg_b, "same-text", kb, err));
    BOOST_CHECK(ka != kb);
    BOOST_REQUIRE(PutPrivatePrefix("tenant-a", cfg_a, "same-text", CompleteKv(), ec, err));
    UniValue got;
    BOOST_CHECK(!GetPrivatePrefix("tenant-a", "tenant-a", cfg_b, "same-text", got, ec, err));
    BOOST_CHECK_EQUAL(ec, "PREFIX_INCOMPATIBLE");
}

BOOST_AUTO_TEST_CASE(JIT_KV_03)
{
    // JIT-KV-03 — Tokenizer/position invalidation
    ResetCapabilityPrefetchForTests();
    std::string ec, err;
    const UniValue base = KvConfig("lora-a@1.0", "tok-v1", "rope-ntk");
    BOOST_REQUIRE(PutPrivatePrefix("tenant-a", base, "hello", CompleteKv(), ec, err));
    UniValue got;
    UniValue tok = KvConfig("lora-a@1.0", "tok-v2", "rope-ntk");
    BOOST_CHECK(!GetPrivatePrefix("tenant-a", "tenant-a", tok, "hello", got, ec, err));
    UniValue rope = KvConfig("lora-a@1.0", "tok-v1", "rope-linear");
    BOOST_CHECK(!GetPrivatePrefix("tenant-a", "tenant-a", rope, "hello", got, ec, err));
    Digest48 k0{}, k1{}, k2{};
    BOOST_REQUIRE(PrivatePrefixKey("tenant-a", base, "hello", k0, err));
    BOOST_REQUIRE(PrivatePrefixKey("tenant-a", tok, "hello", k1, err));
    BOOST_REQUIRE(PrivatePrefixKey("tenant-a", rope, "hello", k2, err));
    BOOST_CHECK(k0 != k1);
    BOOST_CHECK(k0 != k2);
}

BOOST_AUTO_TEST_CASE(JIT_KV_04)
{
    // JIT-KV-04 — Cross-tenant denial
    ResetCapabilityPrefetchForTests();
    std::string ec, err;
    const UniValue cfg = KvConfig("lora-a@1.0", "tok-v1", "rope-ntk");
    Digest48 ka{}, kb{};
    BOOST_REQUIRE(PrivatePrefixKey("tenant-a", cfg, "common-prefix", ka, err));
    BOOST_REQUIRE(PrivatePrefixKey("tenant-b", cfg, "common-prefix", kb, err));
    BOOST_CHECK(ka != kb);
    BOOST_CHECK(!PrefixVisibleToTenant("tenant-a", "tenant-b"));
    BOOST_CHECK(PrefixVisibleToTenant("tenant-a", "tenant-a"));
    BOOST_CHECK(!PrefixVisibleToTenant("public", "public"));
    BOOST_CHECK(!PrefixVisibleToTenant("PUBLIC", "PUBLIC"));
    BOOST_CHECK(!PrefixVisibleToTenant("anonymous", "anonymous"));
    BOOST_REQUIRE(PutPrivatePrefix("tenant-a", cfg, "common-prefix", CompleteKv(), ec, err));
    UniValue got;
    BOOST_CHECK(!GetPrivatePrefix("tenant-b", "tenant-a", cfg, "common-prefix", got, ec, err));
    BOOST_CHECK_EQUAL(ec, "PREFIX_INCOMPATIBLE");
    BOOST_CHECK(!got.exists("output_digest"));
    BOOST_CHECK(!GetPrivatePrefix("tenant-b", "tenant-b", cfg, "common-prefix", got, ec, err));
    BOOST_CHECK(!got.exists("output_digest"));
    BOOST_CHECK(!GetPrivatePrefix("public", "tenant-a", cfg, "common-prefix", got, ec, err));
    BOOST_CHECK_EQUAL(ec, "PREFIX_INCOMPATIBLE");
    BOOST_CHECK(!got.exists("output_digest"));
    BOOST_CHECK(!GetPrivatePrefix("PUBLIC", "tenant-a", cfg, "common-prefix", got, ec, err));
    BOOST_CHECK(!GetPrivatePrefix("anonymous", "tenant-a", cfg, "common-prefix", got, ec, err));
    BOOST_CHECK(!got.exists("output_digest"));
}

BOOST_AUTO_TEST_CASE(JIT_KV_05)
{
    // JIT-KV-05 — Incomplete write
    ResetCapabilityPrefetchForTests();
    std::string ec, err;
    const UniValue cfg = KvConfig("lora-a@1.0", "tok-v1", "rope-ntk");
    UniValue partial = CompleteKv();
    partial.pushKV("complete_layers", 1);
    partial.pushKV("expected_layers", 4);
    partial.pushKV("crash_mid_persist", true);
    partial.pushKV("persist_complete", false);
    BOOST_REQUIRE(PutPrivatePrefix("tenant-a", cfg, "mid-write", partial, ec, err));
    UniValue got;
    BOOST_CHECK(!GetPrivatePrefix("tenant-a", "tenant-a", cfg, "mid-write", got, ec, err));
    SimulatePrivatePrefixRestart();
    BOOST_CHECK(!GetPrivatePrefix("tenant-a", "tenant-a", cfg, "mid-write", got, ec, err));
    BOOST_REQUIRE(PutPrivatePrefix("tenant-a", cfg, "mid-write", CompleteKv(), ec, err));
    BOOST_REQUIRE(GetPrivatePrefix("tenant-a", "tenant-a", cfg, "mid-write", got, ec, err));
}

BOOST_AUTO_TEST_CASE(JIT_KV_06)
{
    // JIT-KV-06 — Telemetry isolation
    ResetCapabilityPrefetchForTests();
    const UniValue tel = PrivatePrefixTelemetry("tenant-a");
    const std::string dumped = tel.write();
    BOOST_CHECK(tel["public_announce"].isFalse());
    BOOST_CHECK(tel["public_discovery"].isFalse());
    BOOST_CHECK(tel["lmcache_remote"].isFalse());
    BOOST_CHECK(tel["controller_telemetry"].isFalse());
    BOOST_CHECK(tel["analytics_sink"].isFalse());
    BOOST_CHECK(dumped.find("prompt") == std::string::npos);
    BOOST_CHECK(dumped.find("token_prefix") == std::string::npos);
    BOOST_CHECK(dumped.find("hit_rate") == std::string::npos);
    BOOST_CHECK_EQUAL(tel["automatic_spend_atoms"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_CASE(JIT_KV_07)
{
    // JIT-KV-07 — Retire persistent state
    ResetCapabilityPrefetchForTests();
    std::string ec, err;
    const UniValue cfg = KvConfig("lora-a@1.0", "tok-v1", "rope-ntk");
    Digest48 before{};
    BOOST_REQUIRE(PrivatePrefixKey("tenant-a", cfg, "keep", before, err));
    BOOST_REQUIRE(PutPrivatePrefix("tenant-a", cfg, "keep", CompleteKv(), ec, err));
    UniValue report;
    BOOST_REQUIRE(RetirePrivatePrefix("tenant-a", /*rotate_key=*/true, /*active_lease=*/true, report, err));
    BOOST_CHECK(report["new_access"].isFalse());
    BOOST_CHECK(report["active_draining"].isTrue());
    BOOST_CHECK(report["active_drained"].isFalse());
    BOOST_CHECK_EQUAL(report["persistence"].get_str(), "key_retired");
    BOOST_CHECK(report["secure_erase_guaranteed"].isTrue());
    UniValue got;
    BOOST_CHECK(!GetPrivatePrefix("tenant-a", "tenant-a", cfg, "keep", got, ec, err));
    Digest48 after{};
    BOOST_REQUIRE(PrivatePrefixKey("tenant-a", cfg, "keep", after, err));
    BOOST_CHECK(before != after);
}

BOOST_AUTO_TEST_CASE(JIT_CACHE_TENANT_ISOLATION)
{
    // Derived executable cache must not collide or leak across tenants
    // (compiler/runtime/dtype/shape/model_digest is not a tenant key).
    ResetCapabilityPrefetchForTests();
    std::string ec, err;
    UniValue vis;
    UniValue a = MakeCache();
    a.pushKV("tenant", "tenant-a");
    a.pushKV("scope", "LOCAL_USER");
    a.pushKV("adapters", "lora-secret-a");
    a.pushKV("source_recipe_id", std::string(96, '1'));
    a.pushKV("secret_payload", "tenant-a-only");
    BOOST_REQUIRE(CommitExecutableCache(a, /*crash_before_promote=*/false, vis, ec, err));

    UniValue hit;
    BOOST_REQUIRE(LookupExecutableCache(a, hit, ec, err));
    BOOST_CHECK(hit["hit"].isTrue());
    BOOST_CHECK_EQUAL(hit["body"]["secret_payload"].get_str(), "tenant-a-only");

    UniValue b = MakeCache();
    b.pushKV("tenant", "tenant-b");
    b.pushKV("scope", "LOCAL_USER");
    b.pushKV("adapters", "lora-other");
    b.pushKV("source_recipe_id", std::string(96, '1'));
    BOOST_CHECK(!LookupExecutableCache(b, hit, ec, err));
    BOOST_CHECK_EQUAL(ec, "CACHE_MISS");
    BOOST_CHECK(hit["hit"].isFalse());
    BOOST_CHECK(!hit.exists("body"));

    BOOST_TEST_CONTEXT("tenant-a cache key not visible to tenant-b") {
        UniValue probe = a;
        probe.pushKV("requester", "tenant-b");
        BOOST_CHECK(!LookupExecutableCache(probe, hit, ec, err));
        BOOST_CHECK_EQUAL(ec, "CACHE_MISS");
        BOOST_CHECK(hit["hit"].isFalse());
        BOOST_CHECK(!hit.exists("body"));
        UniValue as_public = a;
        as_public.pushKV("requester", "public");
        BOOST_CHECK(!LookupExecutableCache(as_public, hit, ec, err));
        BOOST_CHECK_EQUAL(ec, "CACHE_MISS");
        BOOST_CHECK(!hit.exists("body"));
        UniValue as_anon = a;
        as_anon.pushKV("requester", "anonymous");
        BOOST_CHECK(!LookupExecutableCache(as_anon, hit, ec, err));
        BOOST_CHECK_EQUAL(ec, "CACHE_MISS");
        BOOST_CHECK(!hit.exists("body"));
        UniValue owner_b = a;
        owner_b.pushKV("owner_tenant", "tenant-b");
        owner_b.pushKV("tenant", "tenant-b");
        BOOST_CHECK(!LookupExecutableCache(owner_b, hit, ec, err));
        BOOST_CHECK_EQUAL(ec, "CACHE_MISS");
        BOOST_CHECK(!hit.exists("body"));
    }

    UniValue unscoped = MakeCache();
    BOOST_CHECK(!LookupExecutableCache(unscoped, hit, ec, err));
    BOOST_CHECK_EQUAL(ec, "CACHE_MISS");
    BOOST_CHECK(!hit.exists("body"));

    Digest48 fa{}, fb{};
    BOOST_REQUIRE(ExecutableCacheFingerprint(a, fa, err));
    BOOST_REQUIRE(ExecutableCacheFingerprint(b, fb, err));
    BOOST_CHECK(fa != fb);

    UniValue vis_b;
    BOOST_REQUIRE(CommitExecutableCache(b, false, vis_b, ec, err));
    BOOST_REQUIRE(LookupExecutableCache(a, hit, ec, err));
    BOOST_CHECK_EQUAL(hit["body"]["secret_payload"].get_str(), "tenant-a-only");
    BOOST_CHECK_EQUAL(hit["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue public_tenant = MakeCache();
    public_tenant.pushKV("tenant", "PUBLIC_MODEL");
    BOOST_CHECK(!CommitExecutableCache(public_tenant, false, vis, ec, err));
    BOOST_CHECK_EQUAL(ec, "PREFIX_INCOMPATIBLE");

    UniValue reclass = a;
    reclass.pushKV("scope", "PUBLIC_MODEL");
    BOOST_CHECK(!CommitExecutableCache(reclass, false, vis, ec, err));
    BOOST_CHECK_EQUAL(ec, "PREFIX_INCOMPATIBLE");
    BOOST_REQUIRE(LookupExecutableCache(a, hit, ec, err));
    BOOST_CHECK_EQUAL(hit["body"]["secret_payload"].get_str(), "tenant-a-only");
    BOOST_CHECK_EQUAL(hit["body"]["scope"].get_str(), "LOCAL_USER");
}

BOOST_AUTO_TEST_CASE(JIT_CACHE_DERIVED_RECIPE)
{
    // source_recipe_id / recipe_id must not alias model_digest (CapabilityObjectIdJson
    // also drops top-level recipe_id, so it is rebound as source_recipe_id).
    ResetCapabilityPrefetchForTests();
    std::string ec, err;
    UniValue vis;
    UniValue r1 = MakeCache();
    r1.pushKV("source_recipe_id", std::string(96, '1'));
    BOOST_REQUIRE(CommitExecutableCache(r1, false, vis, ec, err));

    UniValue r2 = MakeCache();
    r2.pushKV("source_recipe_id", std::string(96, '2'));
    UniValue hit;
    BOOST_CHECK(!LookupExecutableCache(r2, hit, ec, err));
    BOOST_CHECK_EQUAL(ec, "CACHE_MISS");
    BOOST_CHECK(hit["hit"].isFalse());

    Digest48 d1{}, d2{}, d_recipe{};
    BOOST_REQUIRE(ExecutableCacheFingerprint(r1, d1, err));
    BOOST_REQUIRE(ExecutableCacheFingerprint(r2, d2, err));
    BOOST_CHECK(d1 != d2);

    UniValue as_recipe_id = MakeCache();
    as_recipe_id.pushKV("recipe_id", std::string(96, '1'));
    BOOST_REQUIRE(ExecutableCacheFingerprint(as_recipe_id, d_recipe, err));
    BOOST_CHECK(d1 == d_recipe);

    UniValue only_model = MakeCache();
    Digest48 d_model{};
    BOOST_REQUIRE(ExecutableCacheFingerprint(only_model, d_model, err));
    BOOST_CHECK(d1 != d_model);
}

BOOST_AUTO_TEST_CASE(JIT_KV_PREFIX_VISIBLE_HOLES)
{
    // Empty, public, and scope-enum tenant ids are not a shared KV identity.
    ResetCapabilityPrefetchForTests();
    BOOST_CHECK(!PrefixVisibleToTenant("", ""));
    BOOST_CHECK(!PrefixVisibleToTenant("", "tenant-a"));
    BOOST_CHECK(!PrefixVisibleToTenant("tenant-a", ""));
    BOOST_CHECK(!PrefixVisibleToTenant("*", "*"));
    BOOST_CHECK(!PrefixVisibleToTenant("public", "public"));
    BOOST_CHECK(!PrefixVisibleToTenant("PUBLIC", "PUBLIC"));
    BOOST_CHECK(!PrefixVisibleToTenant("Public", "Public"));
    BOOST_CHECK(!PrefixVisibleToTenant("PUBLIC_MODEL", "PUBLIC_MODEL"));
    BOOST_CHECK(!PrefixVisibleToTenant("public_model", "public_model"));
    BOOST_CHECK(!PrefixVisibleToTenant("anonymous", "anonymous"));
    BOOST_CHECK(!PrefixVisibleToTenant("ANONYMOUS", "ANONYMOUS"));
    BOOST_CHECK(!PrefixVisibleToTenant("Anonymous", "Anonymous"));
    BOOST_CHECK(!PrefixVisibleToTenant(" anonymous ", " anonymous "));
    BOOST_CHECK(!PrefixVisibleToTenant("ORGANIZATION", "ORGANIZATION"));
    BOOST_CHECK(!PrefixVisibleToTenant("LOCAL_USER", "LOCAL_USER"));
    BOOST_CHECK(!PrefixVisibleToTenant("local_user", "local_user"));
    BOOST_CHECK(PrefixVisibleToTenant("tenant-a", "tenant-a"));
    BOOST_CHECK(!PrefixVisibleToTenant("tenant-a", "tenant-a-admin"));
    BOOST_CHECK(!PrefixVisibleToTenant("public", "tenant-a"));
    BOOST_CHECK(!PrefixVisibleToTenant("tenant-a", "anonymous"));

    std::string ec, err;
    const UniValue cfg = KvConfig("lora-a@1.0", "tok-v1", "rope-ntk");
    Digest48 k{};
    BOOST_CHECK(!PrivatePrefixKey("", cfg, "p", k, err));
    BOOST_CHECK(!PrivatePrefixKey("PUBLIC_MODEL", cfg, "p", k, err));
    BOOST_CHECK(!PrivatePrefixKey("PUBLIC", cfg, "p", k, err));
    BOOST_CHECK(!PrivatePrefixKey("public", cfg, "p", k, err));
    BOOST_CHECK(!PrivatePrefixKey("anonymous", cfg, "p", k, err));
    BOOST_CHECK(!PrivatePrefixKey("ANONYMOUS", cfg, "p", k, err));
    BOOST_CHECK(!PrivatePrefixKey("ORGANIZATION", cfg, "p", k, err));
    BOOST_CHECK(!PutPrivatePrefix("", cfg, "p", CompleteKv(), ec, err));
    BOOST_CHECK_EQUAL(ec, "PREFIX_INCOMPATIBLE");
    BOOST_CHECK(!PutPrivatePrefix("public", cfg, "p", CompleteKv(), ec, err));
    BOOST_CHECK_EQUAL(ec, "PREFIX_INCOMPATIBLE");
    BOOST_CHECK(!PutPrivatePrefix("PUBLIC", cfg, "p", CompleteKv(), ec, err));
    BOOST_CHECK(!PutPrivatePrefix("anonymous", cfg, "p", CompleteKv(), ec, err));
    BOOST_CHECK_EQUAL(ec, "PREFIX_INCOMPATIBLE");
    BOOST_CHECK(!PutPrivatePrefix("ANONYMOUS", cfg, "p", CompleteKv(), ec, err));

    UniValue got;
    BOOST_CHECK(!GetPrivatePrefix("", "", cfg, "p", got, ec, err));
    BOOST_CHECK_EQUAL(ec, "PREFIX_INCOMPATIBLE");
    BOOST_CHECK(!got.exists("output_digest"));
    BOOST_CHECK(!GetPrivatePrefix("ORGANIZATION", "ORGANIZATION", cfg, "p", got, ec, err));
    BOOST_CHECK(!got.exists("output_digest"));
    BOOST_CHECK(!GetPrivatePrefix("anonymous", "anonymous", cfg, "p", got, ec, err));
    BOOST_CHECK(!got.exists("output_digest"));
    BOOST_CHECK(!GetPrivatePrefix("PUBLIC", "PUBLIC", cfg, "p", got, ec, err));
    BOOST_CHECK(!got.exists("output_digest"));
}

BOOST_AUTO_TEST_CASE(JIT_KV_EXPIRED_AND_CHAT_TEMPLATE)
{
    // expires_at_ms must actually invalidate; chat_template is part of the key.
    ResetCapabilityPrefetchForTests();
    std::string ec, err;
    const UniValue cfg = KvConfig("lora-a@1.0", "tok-v1", "rope-ntk");
    UniValue expired = CompleteKv();
    expired.pushKV("expires_at_ms", 1);
    BOOST_REQUIRE(PutPrivatePrefix("tenant-a", cfg, "aged", expired, ec, err));
    UniValue got;
    BOOST_CHECK(!GetPrivatePrefix("tenant-a", "tenant-a", cfg, "aged", got, ec, err));
    BOOST_CHECK_EQUAL(ec, "PREFIX_INCOMPATIBLE");
    BOOST_CHECK(!got.exists("output_digest"));

    UniValue live = CompleteKv();
    live.pushKV("expires_at_ms", "4102444800000");
    BOOST_REQUIRE(PutPrivatePrefix("tenant-a", cfg, "fresh", live, ec, err));
    BOOST_REQUIRE(GetPrivatePrefix("tenant-a", "tenant-a", cfg, "fresh", got, ec, err));
    BOOST_CHECK(got["saved_prefill_work"].isTrue());

    UniValue chat = KvConfig("lora-a@1.0", "tok-v1", "rope-ntk");
    BOOST_REQUIRE(PutPrivatePrefix("tenant-a", chat, "hello", CompleteKv(), ec, err));
    UniValue other_chat = KvConfig("lora-a@1.0", "tok-v1", "rope-ntk");
    other_chat.pushKV("chat_template", "llama3");
    BOOST_CHECK(!GetPrivatePrefix("tenant-a", "tenant-a", other_chat, "hello", got, ec, err));
    BOOST_CHECK_EQUAL(ec, "PREFIX_INCOMPATIBLE");
    Digest48 k0{}, k1{};
    BOOST_REQUIRE(PrivatePrefixKey("tenant-a", chat, "hello", k0, err));
    BOOST_REQUIRE(PrivatePrefixKey("tenant-a", other_chat, "hello", k1, err));
    BOOST_CHECK(k0 != k1);
}

BOOST_AUTO_TEST_SUITE_END()
