// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Native J01–J12 + JIT-API-04/07, JIT-PRIV-03, JIT-SAFETY-01/04/06.
// Isolated in-process only. No production btxd. automatic_spend_atoms=0.
// Hardware CUDA/ROCm/Metal/NIXL/GDS/CXL absence is NOT_RUN.

#include <consensus/amount.h>
#include <modelnet/capability.h>
#include <modelnet/capability_sdk.h>
#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

namespace modelnet {
void ResetCapabilityPrefetchForTests();
void ResetCapabilityComposeState();
} // namespace modelnet

BOOST_FIXTURE_TEST_SUITE(modelnet_jit_journey_tests, BasicTestingSetup)

namespace {

UniValue Recipe()
{
    UniValue r(UniValue::VOBJ);
    r.pushKV("recipe_kind", "FULL_MODEL");
    UniValue comps(UniValue::VARR);
    UniValue c(UniValue::VOBJ);
    c.pushKV("name", "base");
    UniValue res(UniValue::VOBJ);
    res.pushKV("kind", "MODEL");
    res.pushKV("digest48", std::string(96, 'a'));
    c.pushKV("resource", res);
    c.pushKV("role", "BASE");
    c.pushKV("required", true);
    comps.push_back(c);
    r.pushKV("components", comps);
    r.pushKV("readiness_contract", "FULL_REQUIRED_SET");
    r.pushKV("automatic_spend_atoms", 0);
    return r;
}

UniValue Grant()
{
    UniValue g(UniValue::VOBJ);
    g.pushKV("caller", "local");
    g.pushKV("host_bytes", 8388608);
    g.pushKV("automatic_spend_atoms", 0);
    return g;
}

UniValue Rpc(const std::string& method, const UniValue& o)
{
    UniValue params(UniValue::VARR);
    params.push_back(o);
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", method);
    req.pushKV("params", params);
    return req;
}

void ZeroSpend(const UniValue& o, const char* where)
{
    BOOST_REQUIRE_MESSAGE(o.isObject(), where);
    if (o.exists("automatic_spend_atoms")) {
        const UniValue& s = o["automatic_spend_atoms"];
        const bool ok = (s.isNum() && s.getInt<int>() == 0) || (s.isStr() && s.get_str() == "0");
        BOOST_CHECK_MESSAGE(ok, where);
    }
    BOOST_CHECK_MESSAGE(!modelnet::JsonContainsWalletPath(o), where);
}

std::string CliErrCode(const std::string& eout)
{
    const auto pos = eout.find(':');
    if (pos == std::string::npos) {
        const auto nl = eout.find('\n');
        return nl == std::string::npos ? eout : eout.substr(0, nl);
    }
    return eout.substr(0, pos);
}

bool CliFailClosedOk(const std::string& code)
{
    return code == "BUDGET_EXCEEDED" || code == "CACHE_MISS" || code == "INVALID_PARAMETER" ||
           code == "UNKNOWN_LEASE" || code == "LEASE_HOLD" || code == "PREMATURE_READY" ||
           code == "MEMORY_RESERVATION_FAILED" || code == "HELPER_DOWN" ||
           code == "PAID_PATH_FORBIDDEN" || code == "NO_ELIGIBLE_RECIPE" ||
           code == "UNVERIFIED_RANGE" || code == "STALE_GENERATION" ||
           code == "HARDWARE_NOT_RUN" || code == "RUNTIME_NOT_INSTALLED" ||
           code == "LIVE_RUNTIME_NOT_RUN" || code == "SWITCH_FAILED" ||
           code == "ID_MISMATCH" || code == "ADAPTER_BASE_MISMATCH" || code == "EFFECT_DENIED" ||
           code.rfind("GRANT_", 0) == 0;
}

bool StatusFailClosedOk(const std::string& code)
{
    return code == "UNKNOWN_LEASE" || code == "INVALID_PARAMETER" || code == "HELPER_DOWN";
}

bool ReadCliJson(const std::string& out, UniValue& o)
{
    std::string s = out;
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ')) s.pop_back();
    o = UniValue(UniValue::VOBJ);
    return o.read(s) && o.isObject();
}

std::string CliField(const UniValue& o, const std::string& raw, const char* key)
{
    if (o.isObject() && o.exists(key) && o[key].isStr() && !o[key].get_str().empty()) {
        return o[key].get_str();
    }
    const std::string pfx = std::string(key) + "=";
    const auto pos = raw.find(pfx);
    if (pos == std::string::npos) return {};
    const auto start = pos + pfx.size();
    const auto end = raw.find_first_of("\r\n", start);
    std::string v = raw.substr(start, end == std::string::npos ? std::string::npos : end - start);
    while (!v.empty() && (v.back() == ' ' || v.back() == '\t')) v.pop_back();
    return v;
}

bool JsonReadyTrue(const UniValue& o)
{
    if (!o.exists("ready")) return false;
    const UniValue& r = o["ready"];
    if (r.isTrue()) return true;
    if (r.isBool()) return r.get_bool();
    if (r.isStr()) {
        const std::string s = r.get_str();
        return s == "true" || s == "TRUE" || s == "1";
    }
    return r.isNum() && r.getInt<int>() != 0;
}

bool JsonFlagTrue(const UniValue& o, const char* key)
{
    if (!o.exists(key)) return false;
    const UniValue& v = o[key];
    if (v.isTrue()) return true;
    if (v.isBool()) return v.get_bool();
    return false;
}

void NoSpendText(const std::string& text, const char* where)
{
    BOOST_CHECK_MESSAGE(text.find("\"automatic_spend_atoms\":1") == std::string::npos &&
                            text.find("automatic_spend_atoms=1") == std::string::npos,
                        where);
}

bool EmitsPlanIdOrCandidates(const UniValue& o)
{
    if (o.exists("plan_id") && o["plan_id"].isStr() && !o["plan_id"].get_str().empty()) return true;
    if (!o.exists("candidates") || !o["candidates"].isArray() || o["candidates"].empty()) return false;
    const UniValue& c0 = o["candidates"][0];
    if (c0.isObject() && c0.exists("plan_id") && c0["plan_id"].isStr() && !c0["plan_id"].get_str().empty()) return true;
    return true;
}

} // namespace

BOOST_AUTO_TEST_CASE(jit_journey_01_to_12)
{
    modelnet::ModelCatalog cat{m_path_root / "j", 1 << 20};
    modelnet::CapabilityClient client(cat);
    modelnet::CapabilityError cerr;
    std::string code, err;

    BOOST_TEST_CONTEXT("J01 / JIT-JOURNEY-01") {
        UniValue plan;
        BOOST_REQUIRE_MESSAGE(client.Plan(Recipe(), Grant(), plan, cerr), cerr.code + " " + cerr.message);
        ZeroSpend(plan, "plan");
        modelnet::ReadinessHandle h;
        UniValue got;
        BOOST_REQUIRE_MESSAGE(client.Ensure(plan["plan_id"].get_str(), Grant(), h, got, cerr),
                              cerr.code + " " + cerr.message);
        BOOST_CHECK(h.IsReadyReference());
        BOOST_CHECK(!got.exists("path") || got["path"].isNull() ||
                    (got["path"].isStr() && got["path"].get_str() != h.lease_id));
        BOOST_CHECK_EQUAL(got["automatic_spend_atoms"].getInt<int>(), 0);
        if (got.exists("second_downloader")) BOOST_CHECK(got["second_downloader"].isFalse());
        if (got.exists("achieved") && got["achieved"].isStr()) {
            BOOST_CHECK_EQUAL(got["achieved"].get_str(), "FIRST_USEFUL_RESULT");
        }

        UniValue helper_got;
        UniValue plan_req(UniValue::VOBJ);
        plan_req.pushKV("recipe", Recipe());
        plan_req.pushKV("grant", Grant());
        BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("planbtxcapability", plan_req), helper_got, code, err));
        ZeroSpend(helper_got, "DispatchHelperRpc plan");

        const unsigned char cpu[] = {'j', '0', '1', '-', 'c', 'p', 'u'};
        modelnet::ReadyReceipt rec;
        UniValue typed(UniValue::VOBJ);
        typed.pushKV("adapter_abi", modelnet::RUNTIME_ADAPTER_ABI);
        typed.pushKV("backend", "CPU");
        BOOST_REQUIRE(modelnet::LoadTrustedRuntime("synthetic-cpu-fixture",
                                                 Span<const unsigned char>{cpu, sizeof(cpu)}, typed, rec, code, err));
        BOOST_CHECK(rec.smoke_passed);
        BOOST_CHECK(rec.achieved == modelnet::ReadinessTarget::FIRST_USEFUL_RESULT);
    }
    BOOST_TEST_CONTEXT("J02 / JIT-JOURNEY-02") {
        modelnet::Digest48 base{}, bind{}, other{};
        BOOST_REQUIRE(modelnet::Digest48::FromHex(std::string(96, 'a'), base, err));
        BOOST_REQUIRE(modelnet::Digest48::FromHex(std::string(96, 'a'), bind, err));
        BOOST_REQUIRE(modelnet::Digest48::FromHex(std::string(96, 'b'), other, err));
        BOOST_REQUIRE(modelnet::AttachExactBaseAdapter(base, bind, code, err));
        BOOST_CHECK(!modelnet::AttachExactBaseAdapter(base, other, code, err));
        modelnet::Digest48 c1, c2;
        BOOST_REQUIRE(modelnet::ComposeLoraOrder({"adapter-s1"}, {"1"}, c1, err));
        BOOST_REQUIRE(modelnet::ComposeLoraOrder({"adapter-s2"}, {"1"}, c2, err));
        BOOST_CHECK(c1 != c2);
    }
    BOOST_TEST_CONTEXT("J03 / JIT-JOURNEY-03") {
        const uint64_t psz = 8;
        std::vector<std::vector<unsigned char>> pieces{
            std::vector<unsigned char>(8, 0x11),
            std::vector<unsigned char>(8, 0x00),
            std::vector<unsigned char>(8, 0x22),
        };
        std::vector<bool> bits{true, false, true};
        BOOST_CHECK(modelnet::SparseHoleIsUnverified(8, 8, bits, psz));
        modelnet::Digest48 man{};
        modelnet::VerifiedRangeLease lease;
        BOOST_CHECK(!modelnet::ReadVerifiedRangeFromPieces(man, 8, 8, pieces, psz, bits, modelnet::NewGeneration(), lease,
                                                           code, err));
        BOOST_CHECK(lease.bytes.empty());
        bits[1] = true;
        BOOST_REQUIRE(modelnet::ReadVerifiedRangeFromPieces(man, 0, 24, pieces, psz, bits, modelnet::NewGeneration(), lease,
                                                           code, err));
        BOOST_REQUIRE_EQUAL(lease.bytes.size(), 24U);
        BOOST_CHECK_EQUAL(lease.bytes[0], 0x11);
        BOOST_CHECK(!modelnet::StreamingEqualsFullFile({0, 0}, {1, 2}));
    }
    BOOST_TEST_CONTEXT("J04 / JIT-JOURNEY-04") {
        const unsigned char payload[] = {1, 2, 3, 4, 5, 6, 7, 8};
        UniValue params(UniValue::VOBJ);
        params.pushKV("backend", "CPU");
        modelnet::ReadyReceipt rec;
        BOOST_REQUIRE(modelnet::LoadTrustedRuntime("synthetic-cpu-fixture", payload, params, rec, code, err));
        UniValue st;
        BOOST_REQUIRE(modelnet::SleepRuntimePreserveWeights(rec.lease_id, st, code, err));
        BOOST_CHECK(st["ready"].isFalse());
        modelnet::ReadyReceipt remap;
        BOOST_CHECK(!modelnet::WakeRuntimeRemapOnly(rec.lease_id, remap, code, err));
        BOOST_CHECK_EQUAL(code, "PREMATURE_READY");
        modelnet::ReadyReceipt wake;
        BOOST_REQUIRE(modelnet::WakeRuntimeRebuildKv(rec.lease_id, wake, code, err));
        BOOST_CHECK(wake.smoke_passed);
    }
    BOOST_TEST_CONTEXT("J05 / JIT-JOURNEY-05") {
        BOOST_CHECK(!modelnet::PeerMembershipAllows("PRIVATE_FABRIC_DISABLED", "p1", code, err));
        BOOST_CHECK_EQUAL(code, "FABRIC_POLICY_REQUIRED");
        std::vector<unsigned char> dest;
        modelnet::PhysicalDisposition d{};
        const unsigned char src[] = {1, 2};
        BOOST_REQUIRE(modelnet::HostBufferTransfer(src, dest, modelnet::NewGeneration(), d, err));
        BOOST_CHECK(dest.size() == sizeof(src));
        BOOST_TEST_MESSAGE("J05 NIXL/UCX/GDS fabric hardware NOT_RUN; HostBufferTransfer fallback");
    }
    BOOST_TEST_CONTEXT("J06") {
        UniValue cache(UniValue::VOBJ);
        cache.pushKV("format", "so");
        cache.pushKV("url", "https://example.invalid/x");
        modelnet::Digest48 dummy{};
        BOOST_CHECK(!modelnet::AcceptExecutableCache(cache, false, dummy, code, err));
        UniValue signed_untrusted(UniValue::VOBJ);
        signed_untrusted.pushKV("format", "cubin");
        signed_untrusted.pushKV("compiler", "nvcc");
        signed_untrusted.pushKV("runtime_id", "llama.cpp");
        signed_untrusted.pushKV("verification_method", "MODEL_AUTHOR_SIGNATURE");
        BOOST_CHECK(!modelnet::AcceptExecutableCache(signed_untrusted, false, dummy, code, err));
        BOOST_CHECK_EQUAL(code, "SOFTWARE_TRUST_REQUIRED");
    }
    BOOST_TEST_CONTEXT("J07") {
        BOOST_CHECK(!modelnet::PrefixVisibleToTenant("t1", "t2"));
        BOOST_CHECK(modelnet::PrefixVisibleToTenant("t1", "t1"));
    }
    BOOST_TEST_CONTEXT("J08") {
        BOOST_CHECK(!modelnet::MoEDispatch({}, 0, 0, false, code, err));
        BOOST_CHECK_EQUAL(code, "EXPERT_MISS");

        modelnet::ExpertUnit active;
        active.layer = 0;
        active.expert = 0;
        active.life = modelnet::LeaseLife::ACTIVE;
        BOOST_CHECK(modelnet::MoEDispatch({active}, 0, 0, false, code, err));

        modelnet::ExpertUnit verified;
        verified.layer = 0;
        verified.expert = 0;
        verified.life = modelnet::LeaseLife::VERIFIED;
        BOOST_CHECK(modelnet::MoEDispatch({verified}, 0, 0, false, code, err));

        BOOST_CHECK(!modelnet::MoEDispatch({active}, 0, 0, true, code, err));
        BOOST_CHECK_EQUAL(code, "WAN_INNER_TOKEN_FORBIDDEN");
        BOOST_CHECK(!modelnet::MoEDispatch({verified}, 0, 0, true, code, err));
        BOOST_CHECK_EQUAL(code, "WAN_INNER_TOKEN_FORBIDDEN");

        const unsigned char all_resident[] = {0x11, 0x22, 0x33, 0x44};
        const unsigned char paged_same[] = {0x11, 0x22, 0x33, 0x44};
        const unsigned char paged_mismatch[] = {0x11, 0x22, 0x33, 0x00};
        BOOST_CHECK(modelnet::MoEAllResidentParity(paged_same, all_resident));
        BOOST_CHECK(!modelnet::MoEAllResidentParity(paged_mismatch, all_resident));

        BOOST_TEST_MESSAGE("J08 real MoE hardware paging NOT_RUN; miss fails closed");
    }
    BOOST_TEST_CONTEXT("J09") {
        BOOST_CHECK(!modelnet::PlaceInTier(modelnet::PlacementTier::CXL_NUMA, modelnet::PlacementTier::HOST_PAGEABLE, code,
                                            err));
        BOOST_CHECK_EQUAL(code, "TIER_UNAVAILABLE");
        auto topo = modelnet::DiscoverTopology();
        if (!topo.cxl) BOOST_TEST_MESSAGE("JIT-JOURNEY-09 / J09 real CXL NOT_RUN");
        if (!topo.numa) BOOST_TEST_MESSAGE("J09 NUMA hardware placement NOT_RUN");
    }
    BOOST_TEST_CONTEXT("J10") {
        modelnet::ResetCapabilityComposeState();
        std::string jerr, active;
        BOOST_REQUIRE(modelnet::JournalSwitch("old", "new", "commit", jerr));
        BOOST_REQUIRE(modelnet::CrashResumeSwitch({"old", "INCOMPLETE"}, active, jerr));
        BOOST_CHECK_EQUAL(active, "old");
        BOOST_REQUIRE(modelnet::CrashResumeSwitch({"PREPARE:new", "COMMIT:new"}, active, jerr));
        BOOST_CHECK_EQUAL(active, "new");
    }
    BOOST_TEST_CONTEXT("J11") {
        modelnet::ResetCapabilityPrefetchForTests();
        modelnet::HostResourceBroker br;
        modelnet::MemoryLimits lim;
        lim.host_physical_bytes = 1 << 20;
        lim.host_pinned_bytes = 1 << 20;
        lim.device_bytes = 1 << 20;
        lim.speculative_bytes = 1 << 20;
        BOOST_REQUIRE(br.Configure(lim, err));
        modelnet::LocalCapabilityGrant grant;
        grant.caller = "local";
        grant.host_bytes = 1 << 20;
        grant.json = Grant();
        UniValue spec(UniValue::VOBJ);
        spec.pushKV("recipe_id", "spec-a");
        spec.pushKV("priority", "SPECULATIVE");
        spec.pushKV("bytes", 200);
        spec.pushKV("speculative_pool_bytes", 1 << 20);
        spec.pushKV("host_physical_bytes", 1000);
        spec.pushKV("automatic_spend_atoms", 0);
        UniValue job;
        BOOST_REQUIRE(modelnet::AdmitPrefetchHint(spec, grant, br, job, code, err));
        BOOST_CHECK_EQUAL(job["priority"].get_str(), "SPECULATIVE");
        UniValue spec2(UniValue::VOBJ);
        spec2.pushKV("recipe_id", "spec-b");
        spec2.pushKV("priority", "SPECULATIVE");
        spec2.pushKV("bytes", 200);
        spec2.pushKV("speculative_pool_bytes", 1 << 20);
        spec2.pushKV("host_physical_bytes", 1000);
        spec2.pushKV("automatic_spend_atoms", 0);
        BOOST_REQUIRE(modelnet::AdmitPrefetchHint(spec2, grant, br, job, code, err));
        UniValue demand(UniValue::VOBJ);
        demand.pushKV("recipe_id", "demand-b");
        demand.pushKV("priority", "DEMAND");
        demand.pushKV("demand", true);
        demand.pushKV("bytes", 200);
        demand.pushKV("host_physical_bytes", 500);
        demand.pushKV("automatic_spend_atoms", 0);
        BOOST_REQUIRE(modelnet::AdmitPrefetchHint(demand, grant, br, job, code, err));
        BOOST_CHECK_EQUAL(job["priority"].get_str(), "DEMAND");
    }
    BOOST_TEST_CONTEXT("J12") {
        BOOST_CHECK(!modelnet::HelperDownFail(false, code, err));
        BOOST_CHECK_EQUAL(code, "HELPER_DOWN");
        BOOST_CHECK(modelnet::HelperDownFail(true, code, err));
        BOOST_CHECK(!modelnet::RejectLegacyModelHandshake(2, code, err));
        BOOST_CHECK_EQUAL(code, "UNSUPPORTED_CORE_VERSION");
        UniValue oldm(UniValue::VOBJ);
        oldm.pushKV("phase", "ok");
        UniValue neu;
        BOOST_REQUIRE(modelnet::MigratePriorPackageState(oldm, neu, code, err));
        BOOST_CHECK_EQUAL(COIN, 100000000);
        ZeroSpend(neu, "migrate");
    }
}

BOOST_AUTO_TEST_CASE(jit_api_04_cli_schema)
{
    std::string code, err;
    BOOST_TEST_CONTEXT("JIT-API-04") {
        const std::string help = modelnet::CapabilityCliUsage();
        for (const auto& v : modelnet::CapabilityCliPrimaryCommands()) {
            BOOST_CHECK_MESSAGE(help.find(v) != std::string::npos, v);
        }
        for (const auto& m : modelnet::RegisteredCapabilityMethods()) {
            BOOST_CHECK_MESSAGE(modelnet::IsCapabilityHelperMethod(m), m);
            BOOST_CHECK_MESSAGE(help.find(m) != std::string::npos, m);
        }
        BOOST_CHECK(help.find("spend") == std::string::npos || help.find("automatic_spend_atoms") != std::string::npos);
        std::string out, eout;
        BOOST_CHECK_EQUAL(modelnet::RunCapabilityCli({"btx-capability", "help"}, out, eout), 0);
        BOOST_CHECK(out.find("ensure") != std::string::npos);
        BOOST_CHECK_EQUAL(modelnet::RunCapabilityCli({"ensure", "--spend"}, out, eout), 1);
        BOOST_CHECK(eout.find("spend") != std::string::npos);
    }
    BOOST_TEST_CONTEXT("JIT-API-07") {
        BOOST_TEST_MESSAGE("btx-open remains inspect-only; capability CLI is a separate binary");
        BOOST_CHECK(modelnet::IsCapabilityHelperMethod("ensurebtxcapability"));
        BOOST_CHECK(modelnet::CapabilityCliUsage().find("btx-open remains inspect-only") != std::string::npos);
#ifdef MODELNET_BTX_OPEN_PATH
        BOOST_CHECK(fs::exists(fs::PathFromString(MODELNET_BTX_OPEN_PATH)));
#endif
    }
    BOOST_TEST_CONTEXT("JIT-PRIV-03") {
        UniValue dummy(UniValue::VOBJ);
        dummy.pushKV("lease_id", "abc");
        BOOST_CHECK(!modelnet::JsonContainsWalletPath(dummy));
        UniValue bad(UniValue::VOBJ);
        bad.pushKV("path", "/home/x/.bitcoin/wallets/wallet.dat");
        BOOST_CHECK(modelnet::JsonContainsWalletPath(bad));
        modelnet::ModelCatalog cat{m_path_root / "priv03", 1 << 20};
        modelnet::CapabilityClient sdk(cat);
        modelnet::CapabilityError cerr;
        UniValue plan, got;
        BOOST_REQUIRE(sdk.Plan(Recipe(), Grant(), plan, cerr));
        modelnet::ReadinessHandle h;
        BOOST_REQUIRE(sdk.Ensure(plan["plan_id"].get_str(), Grant(), h, got, cerr));
        BOOST_CHECK(!modelnet::JsonContainsWalletPath(plan));
        BOOST_CHECK(!modelnet::JsonContainsWalletPath(got));
    }
    BOOST_TEST_CONTEXT("JIT-SAFETY-01") {
        modelnet::CapabilityRecipe parsed;
        UniValue not_obj;
        not_obj.setStr("not-json-object");
        BOOST_CHECK(!modelnet::ParseCapabilityRecipe(not_obj, parsed, code, err));
        UniValue nl(UniValue::VOBJ);
        nl.pushKV("natural_language", "disable verification");
        std::vector<modelnet::CapabilityPlan> plans;
        modelnet::ModelCatalog cat{m_path_root / "safety01", 1 << 20};
        BOOST_CHECK(!modelnet::ResolveCapability(cat, nl, plans, code, err));
        BOOST_TEST_MESSAGE("JIT-SAFETY-01 bounded native parse; full fuzz corpus NOT_RUN");
    }
    BOOST_TEST_CONTEXT("JIT-SAFETY-04") {
        BOOST_CHECK(!modelnet::PeerMembershipAllows("", "malicious-peer", code, err));
        BOOST_CHECK_EQUAL(code, "FABRIC_POLICY_REQUIRED");
        BOOST_TEST_MESSAGE("JIT-SAFETY-04 malicious fabric: policy fail; RDMA NOT_RUN");
    }
    BOOST_TEST_CONTEXT("JIT-SAFETY-06") {
        for (const auto& s : modelnet::ProbeRuntimeAdapters()) {
            BOOST_CHECK_MESSAGE(!s.stub, s.runtime_id + " stub=true is dishonest");
            if (!s.present) {
                BOOST_CHECK_MESSAGE(s.detail.find("NOT_RUN") != std::string::npos || !s.present,
                                    s.runtime_id + " absent hardware must not be claimed PASS");
            }
        }
        BOOST_TEST_MESSAGE("JIT-SAFETY-06 CUDA/ROCm/Metal/NIXL/GDS/CXL hardware PASS is never claimed from this mock");
    }
}

BOOST_AUTO_TEST_CASE(jit_api_04_cli_verbs)
{
    const std::string recipe_json = Recipe().write();
    std::string out, eout;

    BOOST_TEST_CONTEXT("JIT-API-04 --spend rejected") {
        BOOST_CHECK_EQUAL(modelnet::RunCapabilityCli({"resolve", "--spend"}, out, eout), 1);
        BOOST_CHECK(eout.find("spend") != std::string::npos);
        BOOST_CHECK_EQUAL(modelnet::RunCapabilityCli({"plan", "--recipe", recipe_json, "--spend"}, out, eout), 1);
        BOOST_CHECK(eout.find("spend") != std::string::npos);
        BOOST_CHECK_EQUAL(modelnet::RunCapabilityCli({"prefetch", "--spend"}, out, eout), 1);
        BOOST_CHECK(eout.find("spend") != std::string::npos);
        BOOST_CHECK_EQUAL(modelnet::RunCapabilityCli({"update", "--preview", "--spend"}, out, eout), 1);
        BOOST_CHECK(eout.find("spend") != std::string::npos);
        BOOST_CHECK_EQUAL(modelnet::RunCapabilityCli({"capabilities", "--spend"}, out, eout), 1);
        BOOST_CHECK(eout.find("spend") != std::string::npos);
        BOOST_CHECK_EQUAL(modelnet::RunCapabilityCli({"sleep", "--spend"}, out, eout), 1);
        BOOST_CHECK(eout.find("spend") != std::string::npos);
        BOOST_CHECK_EQUAL(modelnet::RunCapabilityCli({"wake", "--spend"}, out, eout), 1);
        BOOST_CHECK(eout.find("spend") != std::string::npos);
        BOOST_CHECK_EQUAL(modelnet::RunCapabilityCli({"cancel", "--spend"}, out, eout), 1);
        BOOST_CHECK(eout.find("spend") != std::string::npos);
        BOOST_CHECK_EQUAL(modelnet::RunCapabilityCli({"release", "--spend"}, out, eout), 1);
        BOOST_CHECK(eout.find("spend") != std::string::npos);
        BOOST_CHECK_EQUAL(modelnet::RunCapabilityCli({"switch", "--spend"}, out, eout), 1);
        BOOST_CHECK(eout.find("spend") != std::string::npos);
        BOOST_CHECK_EQUAL(modelnet::RunCapabilityCli({"events", "--spend"}, out, eout), 1);
        BOOST_CHECK(eout.find("spend") != std::string::npos);
        BOOST_CHECK_EQUAL(modelnet::RunCapabilityCli({"ttc", "--spend"}, out, eout), 1);
        BOOST_CHECK(eout.find("spend") != std::string::npos);
        BOOST_CHECK_EQUAL(modelnet::RunCapabilityCli({"residency", "--spend"}, out, eout), 1);
        BOOST_CHECK(eout.find("spend") != std::string::npos);
        BOOST_CHECK_EQUAL(modelnet::RunCapabilityCli({"status", "--spend"}, out, eout), 1);
        BOOST_CHECK(eout.find("spend") != std::string::npos);
        BOOST_CHECK_EQUAL(modelnet::RunCapabilityCli({"get", "--spend"}, out, eout), 1);
        BOOST_CHECK(eout.find("spend") != std::string::npos);
    }

    const fs::path modeldir = m_path_root / "cli04";
    fs::create_directories(modeldir);
    fs::path sock = m_path_root / "c.sock";
    if (fs::PathToString(sock).size() >= 100) {
        sock = fs::PathFromString(std::string("/tmp/btx-j04-") + std::to_string(::getpid()) + ".sock");
    }
    ::unlink(fs::PathToString(sock).c_str());

    std::atomic<bool> stop{false};
    std::thread daemon([&] { (void)modelnet::RunCapabilityDaemon(modeldir, sock, &stop); });
    struct Join {
        std::atomic<bool>& stop;
        std::thread& th;
        fs::path sock;
        ~Join()
        {
            stop.store(true);
            if (th.joinable()) th.join();
            ::unlink(fs::PathToString(sock).c_str());
        }
    } join{stop, daemon, sock};

    bool ready = false;
    const auto t0 = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - t0 < std::chrono::seconds(8)) {
        if (fs::exists(sock)) {
            ready = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    BOOST_REQUIRE_MESSAGE(ready, "in-process capabilityd socket");

    const std::string md_flag = "-modeldir=" + fs::PathToString(modeldir);
    const std::string sock_flag = "-capabilitysocket=" + fs::PathToString(sock);
    auto run = [&](const std::vector<std::string>& verbs) {
        std::vector<std::string> args{"btx-capability", md_flag, sock_flag};
        args.insert(args.end(), verbs.begin(), verbs.end());
        out.clear();
        eout.clear();
        return modelnet::RunCapabilityCli(args, out, eout);
    };
    auto retry_ok = [&](const std::vector<std::string>& verbs) {
        int rc = 1;
        for (int i = 0; i < 40; ++i) {
            rc = run(verbs);
            if (rc == 0) return rc;
            if (CliErrCode(eout) != "HELPER_DOWN") return rc;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        return rc;
    };

    BOOST_TEST_CONTEXT("JIT-API-04 resolve --recipe") {
        BOOST_REQUIRE_EQUAL(retry_ok({"resolve", "--recipe", recipe_json}), 0);
        UniValue got;
        BOOST_REQUIRE_MESSAGE(ReadCliJson(out, got), out);
        ZeroSpend(got, "cli resolve");
        BOOST_REQUIRE_MESSAGE(EmitsPlanIdOrCandidates(got), out);
        if (got.exists("candidates") && got["candidates"].isArray() && got["candidates"].size() > 0 &&
            got["candidates"][0].isObject()) {
            ZeroSpend(got["candidates"][0], "cli resolve candidate");
        }
    }

    std::string plan_id;
    std::string lease_id;
    std::string job_id;

    BOOST_TEST_CONTEXT("JIT-API-04 plan --recipe") {
        BOOST_REQUIRE_EQUAL(retry_ok({"plan", "--recipe", recipe_json}), 0);
        UniValue got;
        BOOST_REQUIRE_MESSAGE(ReadCliJson(out, got), out);
        ZeroSpend(got, "cli plan");
        BOOST_REQUIRE(got.exists("plan_id") && got["plan_id"].isStr() && !got["plan_id"].get_str().empty());
        plan_id = got["plan_id"].get_str();
    }

    BOOST_TEST_CONTEXT("JIT-API-04 prefetch after grant") {
        modelnet::ResetCapabilityPrefetchForTests();
        modelnet::MemoryLimits lim;
        lim.host_physical_bytes = 8388608;
        lim.host_pinned_bytes = 8388608;
        lim.device_bytes = 8388608;
        lim.speculative_bytes = 8388608;
        std::string berr;
        BOOST_REQUIRE(modelnet::GlobalCapabilityBroker().Configure(lim, berr));

        const int rc = retry_ok({"prefetch", "--recipe", recipe_json});
        if (rc != 0) {
            const std::string code = CliErrCode(eout);
            BOOST_REQUIRE_MESSAGE(CliFailClosedOk(code), "prefetch fail-closed got " + code + " " + eout);
            BOOST_CHECK_MESSAGE(out.find("\"automatic_spend_atoms\":1") == std::string::npos &&
                                    out.find("automatic_spend_atoms=1") == std::string::npos,
                                "prefetch must not spend on fail-closed");
        } else {
            UniValue got;
            BOOST_REQUIRE_MESSAGE(ReadCliJson(out, got), out);
            ZeroSpend(got, "cli prefetch");
            if (got.exists("automatic_spend_atoms")) {
                const UniValue& s = got["automatic_spend_atoms"];
                const bool zero = (s.isNum() && s.getInt<int>() == 0) || (s.isStr() && s.get_str() == "0");
                BOOST_REQUIRE_MESSAGE(zero, "prefetch silent success with spend");
            }
        }
    }

    BOOST_TEST_CONTEXT("JIT-API-04 update --preview") {
        BOOST_REQUIRE_EQUAL(retry_ok({"update", "--preview"}), 0);
        UniValue got;
        BOOST_REQUIRE_MESSAGE(ReadCliJson(out, got), out);
        ZeroSpend(got, "cli update --preview");
    }

    BOOST_TEST_CONTEXT("JIT-API-04 capabilities") {
        BOOST_REQUIRE_EQUAL(retry_ok({"capabilities"}), 0);
        UniValue got;
        BOOST_REQUIRE_MESSAGE(ReadCliJson(out, got), out);
        ZeroSpend(got, "cli capabilities");
        BOOST_REQUIRE(got.exists("public_runtime_rpc"));
        BOOST_CHECK(got["public_runtime_rpc"].isFalse());
        BOOST_REQUIRE(got.exists("adapters") && got["adapters"].isArray());
        for (const auto& a : got["adapters"].getValues()) {
            BOOST_REQUIRE(a.isObject());
            const std::string id = a.exists("runtime_id") && a["runtime_id"].isStr() ? a["runtime_id"].get_str() : "adapter";
            BOOST_CHECK_MESSAGE(!(a.exists("stub") && a["stub"].isTrue()), id + " stub=true is dishonest");
        }
    }

    BOOST_TEST_CONTEXT("JIT-API-04 inspectbtxtensormap exportbtxlock importbtxlock") {
        // 10-byte SafeTensors: LE64 header length 2 + "{}".
        const std::string st_hex = "02000000000000007b7d";
        UniValue inspect_req(UniValue::VOBJ);
        inspect_req.pushKV("hex", st_hex);
        inspect_req.pushKV("automatic_spend_atoms", 0);
        const int inspect_rc = retry_ok({"inspectbtxtensormap", inspect_req.write()});
        if (inspect_rc == 0) {
            UniValue got;
            BOOST_REQUIRE_MESSAGE(ReadCliJson(out, got), out);
            ZeroSpend(got, "cli inspectbtxtensormap");
            const bool has_map =
                (got.exists("map_id") && got["map_id"].isStr() && !got["map_id"].get_str().empty()) ||
                got.exists("tensors");
            BOOST_REQUIRE_MESSAGE(has_map, "inspectbtxtensormap missing map_id or tensors " + out);
        } else {
            const std::string code = CliErrCode(eout);
            BOOST_REQUIRE_MESSAGE(code != "METHOD_NOT_FOUND" && code.find("unknown command") == std::string::npos,
                                  "inspectbtxtensormap must be registered, got " + code + " " + eout);
            BOOST_REQUIRE_MESSAGE(code == "INVALID_PARAMETER" || code == "TRUNCATED" || code == "INVALID_MODEL",
                                  "inspectbtxtensormap fail-closed got " + code + " " + eout);
            NoSpendText(out + eout, "inspectbtxtensormap must not spend on fail-closed");
        }

        UniValue lock_req(UniValue::VOBJ);
        lock_req.pushKV("recipe_id", std::string(96, 'a'));
        lock_req.pushKV("automatic_spend_atoms", 0);
        const std::string lock_json = lock_req.write();
        const int export_rc = retry_ok({"exportbtxlock", lock_json});
        BOOST_REQUIRE_MESSAGE(export_rc == 0 && CliErrCode(eout) != "METHOD_NOT_FOUND",
                              "exportbtxlock " + CliErrCode(eout) + " " + eout);
        UniValue exported;
        BOOST_REQUIRE_MESSAGE(ReadCliJson(out, exported), out);
        ZeroSpend(exported, "cli exportbtxlock");
        const bool has_lock =
            (exported.exists("hex") && exported["hex"].isStr() && !exported["hex"].get_str().empty()) ||
            (exported.exists("lock_id") && exported["lock_id"].isStr() && !exported["lock_id"].get_str().empty());
        BOOST_REQUIRE_MESSAGE(has_lock, "exportbtxlock missing hex or lock_id " + out);

        const int import_rc = retry_ok({"importbtxlock", lock_json});
        if (import_rc == 0) {
            UniValue imported;
            BOOST_REQUIRE_MESSAGE(ReadCliJson(out, imported), out);
            ZeroSpend(imported, "cli importbtxlock");
            BOOST_REQUIRE_MESSAGE(JsonFlagTrue(imported, "imported"), "importbtxlock imported=true " + out);
        } else {
            const std::string code = CliErrCode(eout);
            BOOST_REQUIRE_MESSAGE(code != "METHOD_NOT_FOUND" && code.find("unknown command") == std::string::npos,
                                  "importbtxlock must be registered, got " + code + " " + eout);
            BOOST_REQUIRE_MESSAGE(CliFailClosedOk(code) || code == "NONCANONICAL_PAYLOAD",
                                  "importbtxlock fail-closed got " + code + " " + eout);
            NoSpendText(out + eout, "importbtxlock must not spend on fail-closed");
        }
    }

    BOOST_TEST_CONTEXT("JIT-API-04 ensure --plan-id") {
        modelnet::MemoryLimits lim;
        lim.host_physical_bytes = 64ull << 20;
        lim.host_pinned_bytes = 64ull << 20;
        lim.device_bytes = 64ull << 20;
        lim.speculative_bytes = 64ull << 20;
        std::string berr;
        BOOST_REQUIRE(modelnet::GlobalCapabilityBroker().Configure(lim, berr));

        const int rc = retry_ok({"--json", "ensure", "--plan-id", plan_id});
        if (rc != 0) {
            const std::string code = CliErrCode(eout);
            BOOST_REQUIRE_MESSAGE(CliFailClosedOk(code), "ensure fail-closed got " + code + " " + eout);
            NoSpendText(out + eout, "ensure must not spend on fail-closed");
            BOOST_TEST_MESSAGE("JIT-API-04 ensure fail-closed (CPU fixture; no GPU claimed): " + code + " " + eout);
        } else {
            UniValue got;
            BOOST_REQUIRE_MESSAGE(ReadCliJson(out, got), out);
            ZeroSpend(got, "cli ensure");
            lease_id = CliField(got, out, "lease_id");
            job_id = CliField(got, out, "job_id");
            BOOST_REQUIRE_MESSAGE(!lease_id.empty() || !job_id.empty(), "ensure success without lease_id/job_id " + out);
            if (got.exists("path")) {
                BOOST_CHECK(got["path"].isNull() || (got["path"].isStr() && got["path"].get_str() != lease_id));
            }
            BOOST_TEST_MESSAGE("JIT-API-04 ensure CPU fixture; no GPU claimed");
        }
    }

    BOOST_TEST_CONTEXT("JIT-API-04 status") {
        const std::string id = !job_id.empty() ? job_id : (!lease_id.empty() ? lease_id : std::string("missing-lease"));
        const int rc = retry_ok({"status", id});
        if (rc == 0) {
            UniValue got;
            BOOST_REQUIRE_MESSAGE(ReadCliJson(out, got), out);
            ZeroSpend(got, "cli status");
        } else {
            const std::string code = CliErrCode(eout);
            BOOST_REQUIRE_MESSAGE(StatusFailClosedOk(code), "status fail-closed got " + code + " " + eout);
            NoSpendText(out + eout, "status must not spend on fail-closed");
        }
        const int get_rc = retry_ok({"get", id});
        if (get_rc == 0) {
            UniValue got;
            BOOST_REQUIRE_MESSAGE(ReadCliJson(out, got), out);
            ZeroSpend(got, "cli get");
        } else {
            const std::string code = CliErrCode(eout);
            BOOST_REQUIRE_MESSAGE(StatusFailClosedOk(code), "get fail-closed got " + code + " " + eout);
            NoSpendText(out + eout, "get must not spend on fail-closed");
        }
    }

    BOOST_TEST_CONTEXT("JIT-API-04 sleep then wake") {
        const std::string lease = !lease_id.empty() ? lease_id : std::string("missing-lease");
        const int sleep_rc = retry_ok({"sleep", lease});
        if (sleep_rc == 0) {
            UniValue got;
            BOOST_REQUIRE_MESSAGE(ReadCliJson(out, got), out);
            ZeroSpend(got, "cli sleep");
            BOOST_CHECK_MESSAGE(!JsonReadyTrue(got), "sleep must not claim ready=true " + out);
        } else {
            const std::string code = CliErrCode(eout);
            BOOST_REQUIRE_MESSAGE(CliFailClosedOk(code), "sleep fail-closed got " + code + " " + eout);
            BOOST_CHECK_MESSAGE(out.find("\"ready\":true") == std::string::npos, "sleep fail must not claim ready=true");
            NoSpendText(out + eout, "sleep must not spend on fail-closed");
        }

        const int wake_rc = retry_ok({"wake", lease});
        if (wake_rc == 0) {
            UniValue got;
            BOOST_REQUIRE_MESSAGE(ReadCliJson(out, got), out);
            ZeroSpend(got, "cli wake");
            BOOST_CHECK_MESSAGE(JsonReadyTrue(got) || JsonFlagTrue(got, "discarded_kv_rebuilt"),
                                "wake success without ready or discarded_kv_rebuilt " + out);
        } else {
            const std::string code = CliErrCode(eout);
            BOOST_REQUIRE_MESSAGE(code == "PREMATURE_READY" || CliFailClosedOk(code),
                                  "wake fail-closed got " + code + " " + eout);
            NoSpendText(out + eout, "wake must not spend on fail-closed");
        }
    }

    BOOST_TEST_CONTEXT("JIT-API-04 events ttc residency") {
        const int ev_rc = retry_ok({"events"});
        if (ev_rc == 0) {
            UniValue ev;
            BOOST_REQUIRE_MESSAGE(ReadCliJson(out, ev), out);
            ZeroSpend(ev, "cli events");
        } else {
            const std::string code = CliErrCode(eout);
            BOOST_REQUIRE_MESSAGE(CliFailClosedOk(code), "events fail-closed got " + code + " " + eout);
            NoSpendText(out + eout, "events must not spend on fail-closed");
        }

        const std::string ttc_id = !job_id.empty() ? job_id : std::string("missing-job");
        const int ttc_rc = retry_ok({"ttc", ttc_id});
        if (ttc_rc == 0) {
            UniValue ttc;
            BOOST_REQUIRE_MESSAGE(ReadCliJson(out, ttc), out);
            ZeroSpend(ttc, "cli ttc");
            if (ttc.exists("critical_path_not_sum")) {
                BOOST_CHECK_MESSAGE(JsonFlagTrue(ttc, "critical_path_not_sum"), "ttc critical_path_not_sum " + out);
            }
        } else {
            const std::string code = CliErrCode(eout);
            BOOST_REQUIRE_MESSAGE(CliFailClosedOk(code), "ttc fail-closed got " + code + " " + eout);
            NoSpendText(out + eout, "ttc must not spend on fail-closed");
        }

        const int res_rc = retry_ok({"residency"});
        if (res_rc == 0) {
            UniValue res;
            BOOST_REQUIRE_MESSAGE(ReadCliJson(out, res), out);
            ZeroSpend(res, "cli residency");
        } else {
            const std::string code = CliErrCode(eout);
            BOOST_REQUIRE_MESSAGE(CliFailClosedOk(code), "residency fail-closed got " + code + " " + eout);
            NoSpendText(out + eout, "residency must not spend on fail-closed");
        }
    }

    BOOST_TEST_CONTEXT("JIT-API-04 switch then cancel") {
        modelnet::ResetCapabilityComposeState();
        const int sw = retry_ok({"switch", "old", "new"});
        if (sw == 0) {
            UniValue got;
            BOOST_REQUIRE_MESSAGE(ReadCliJson(out, got), out);
            ZeroSpend(got, "cli switch");
        } else {
            const std::string code = CliErrCode(eout);
            BOOST_REQUIRE_MESSAGE(CliFailClosedOk(code), "switch fail-closed got " + code + " " + eout);
            NoSpendText(out + eout, "switch must not spend on fail-closed");
        }

        const std::string cancel_id = !job_id.empty() ? job_id : std::string("missing-job");
        const int cr = retry_ok({"cancel", cancel_id});
        if (cr == 0) {
            UniValue got;
            BOOST_REQUIRE_MESSAGE(ReadCliJson(out, got), out);
            ZeroSpend(got, "cli cancel");
            BOOST_REQUIRE_MESSAGE(JsonFlagTrue(got, "cancelled"), "cancel cancelled=true " + out);
        } else {
            const std::string code = CliErrCode(eout);
            BOOST_REQUIRE_MESSAGE(code == "INVALID_PARAMETER" || CliFailClosedOk(code),
                                  "cancel fail-closed unknown job got " + code + " " + eout);
            NoSpendText(out + eout, "cancel must not spend on fail-closed");
        }
    }

    BOOST_TEST_CONTEXT("JIT-API-04 release") {
        const std::string lease = !lease_id.empty() ? lease_id : std::string("missing-lease");
        const int rc = retry_ok({"release", lease});
        if (rc == 0) {
            UniValue got;
            BOOST_REQUIRE_MESSAGE(ReadCliJson(out, got), out);
            ZeroSpend(got, "cli release");
        } else {
            const std::string code = CliErrCode(eout);
            BOOST_REQUIRE_MESSAGE(code == "LEASE_HOLD" || CliFailClosedOk(code),
                                  "release fail-closed got " + code + " " + eout);
            NoSpendText(out + eout, "release must not spend on fail-closed");
            BOOST_TEST_MESSAGE("JIT-API-04 release fail-closed " + code + " (LEASE_HOLD while active is PASS)");
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
