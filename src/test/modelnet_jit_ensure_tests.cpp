// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// BTX-SPEC-0348-CAPABILITY-01 Worker I — native ensure / orchestrator.
//   JIT-BASE-02     TransferSession + GlobalTransferCredits, no second downloader
//   JIT-API-01      EnsureCapability opaque lease, not a bare path
//   JIT-API-03      MEMORY_RESERVATION_FAILED / UNVERIFIED_RANGE / STALE_GENERATION / HELPER_DOWN
//   JIT-API-05      warmup blocked => fixture path not 100% ready
//   JIT-API-06      event compact with explicit gaps, no duplicate side effects
//   JIT-API-08      ensure honesty: IMPLEMENTED_LAB fixture, no canonical acquire claim
//   JIT-UPDATE-01   prepare alongside active (switch_ready false until smoke)
//   JIT-UPDATE-02   failed smoke does not activate
//   JIT-UPDATE-04   SoftwareTrustFloor rejects security rollback
//   JIT-UPDATE-07   idempotent switch; changed digest rejected
//   JIT-JOURNEY-01  cold ensure CPU fixture
//   JIT-JOURNEY-02  resident base via AttachExactBaseAdapter
//   JIT-JOURNEY-04  sleep/wake via SleepRuntimePreserveWeights after LoadTrustedRuntime
//   JIT-JOURNEY-12  HelperDownFail + RejectLegacyModelHandshake + MigratePriorPackageState
//
// Hardware absence: BOOST_TEST_MESSAGE NOT_RUN. Never delete adapters.
// Coordinator owns CMake. Do not ninja from this lane.

#include <modelnet/capability.h>
#include <modelnet/catalog.h>
#include <modelnet/file_stream.h>
#include <modelnet/hello_caps.h>
#include <modelnet/helper.h>
#include <modelnet/transfer_session.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <limits>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_jit_ensure_tests, BasicTestingSetup)

namespace {

UniValue RecipeJson()
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
    return r;
}

UniValue GrantJson(const std::string& caller = "local")
{
    UniValue g(UniValue::VOBJ);
    g.pushKV("caller", caller);
    g.pushKV("host_bytes", 8388608);
    g.pushKV("automatic_spend_atoms", 0);
    return g;
}

modelnet::CapabilityPlan StorePlan()
{
    modelnet::CapabilityRecipe recipe;
    modelnet::LocalCapabilityGrant grant;
    std::string code, err;
    BOOST_REQUIRE(modelnet::ParseCapabilityRecipe(RecipeJson(), recipe, code, err));
    BOOST_REQUIRE(modelnet::ParseGrant(GrantJson(), grant, code, err));
    modelnet::CapabilityPlan plan;
    BOOST_REQUIRE(modelnet::PlanCapability(recipe, nullptr, grant, plan, code, err));
    return plan;
}

UniValue EnsureReq(const modelnet::CapabilityPlan& plan, const std::string& caller = "local")
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("plan_id", plan.plan_id);
    o.pushKV("expected_digest", plan.plan_digest.Hex());
    o.pushKV("grant", GrantJson(caller));
    o.pushKV("automatic_spend_atoms", 0);
    o.pushKV("helper_alive", true);
    return o;
}

bool NoSecrets(const UniValue& o)
{
    const std::string w = o.write();
    return w.find("password") == std::string::npos && w.find("api_key") == std::string::npos &&
           w.find("/home/administrator/.local") == std::string::npos && w.find("hf_token") == std::string::npos;
}

bool OpaqueLease(const UniValue& o)
{
    if (!o.exists("lease_id") || !o["lease_id"].isStr()) return false;
    const std::string id = o["lease_id"].get_str();
    if (id.empty() || id.find('/') != std::string::npos || id.find('\\') != std::string::npos) return false;
    const std::string w = o.write();
    if (w.find("/tmp/btx-capability-ensure") != std::string::npos) return false;
    if (o.exists("path") || o.exists("dest") || o.exists("bare_path")) return false;
    return true;
}

} // namespace

BOOST_AUTO_TEST_CASE(JIT_BASE_02)
{
    BOOST_TEST_MESSAGE("JIT-BASE-02 No duplicate acquisition stack");
    modelnet::ModelCatalog cat{m_path_root / "ensure-cat", 1 << 20};
    BOOST_CHECK(modelnet::GlobalTransferCredits().Ceiling() > 0);
    modelnet::TransferSession live(modelnet::GlobalTransferCredits());
    const auto plan = StorePlan();
    UniValue req = EnsureReq(plan);
    UniValue got;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::EnsureCapability(cat, req, got, code, err), err);
    BOOST_CHECK(got["second_downloader"].isFalse());
    BOOST_CHECK(got["used_global_transfer_credits"].get_bool());
    BOOST_CHECK(got["used_transfer_session"].get_bool());
    BOOST_CHECK_EQUAL(got["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(live.Json().exists("credit_ceiling"));
    BOOST_CHECK(got.write().find("CreditBroker") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(JIT_API_01)
{
    BOOST_TEST_MESSAGE("JIT-API-01 Ensure lifecycle opaque lease");
    modelnet::ModelCatalog cat{m_path_root / "ensure-cat", 1 << 20};
    const auto plan = StorePlan();
    UniValue req = EnsureReq(plan);
    UniValue got;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::EnsureCapability(cat, req, got, code, err), err);
    BOOST_CHECK(OpaqueLease(got));
    BOOST_CHECK(got.exists("job_id"));
    BOOST_CHECK(got.exists("generation"));
    BOOST_CHECK_EQUAL(got["achieved"].get_str(),
                      std::string(modelnet::ReadinessTargetName(modelnet::ReadinessTarget::FIRST_USEFUL_RESULT)));
    BOOST_CHECK(got["smoke_passed"].get_bool());
    BOOST_CHECK_LT(got["progress"]["percent_ready"].getInt<int>(), 100);
    BOOST_CHECK(!got["progress"]["canonical_bytes_verified"].get_bool());
    BOOST_CHECK_EQUAL(got["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(NoSecrets(got));

    UniValue bad_as = EnsureReq(plan, "alice");
    bad_as.pushKV("as", "bob");
    UniValue denied;
    BOOST_CHECK(!modelnet::EnsureCapability(cat, bad_as, denied, code, err));
    BOOST_CHECK_EQUAL(code, "GRANT_WRONG_CALLER");

    UniValue spend = EnsureReq(plan);
    spend.pushKV("automatic_spend_atoms", 1);
    UniValue paid;
    BOOST_CHECK(!modelnet::EnsureCapability(cat, spend, paid, code, err));
    BOOST_CHECK_EQUAL(code, "PAID_PATH_FORBIDDEN");
}

BOOST_AUTO_TEST_CASE(JIT_API_03)
{
    BOOST_TEST_MESSAGE("JIT-API-03 Structured errors");
    modelnet::ModelCatalog cat{m_path_root / "ensure-cat", 1 << 20};
    const auto plan = StorePlan();
    auto check_err = [&](const UniValue& req, const char* expect) {
        UniValue got;
        std::string code, err;
        BOOST_CHECK(!modelnet::EnsureCapability(cat, req, got, code, err));
        BOOST_CHECK_EQUAL(code, expect);
        BOOST_CHECK_EQUAL(got["error_code"].get_str(), expect);
        BOOST_CHECK(got.exists("stage"));
        BOOST_CHECK(got.exists("cleanup"));
        BOOST_CHECK(got.exists("next_action"));
        BOOST_CHECK_EQUAL(got["automatic_spend_atoms"].getInt<int>(), 0);
        BOOST_CHECK(NoSecrets(got));
    };

    UniValue mem = EnsureReq(plan);
    mem.pushKV("inject_error", "MEMORY_RESERVATION_FAILED");
    check_err(mem, "MEMORY_RESERVATION_FAILED");

    UniValue unver = EnsureReq(plan);
    unver.pushKV("inject_error", "UNVERIFIED_RANGE");
    check_err(unver, "UNVERIFIED_RANGE");

    UniValue stale = EnsureReq(plan);
    stale.pushKV("inject_error", "STALE_GENERATION");
    check_err(stale, "STALE_GENERATION");

    UniValue down = EnsureReq(plan);
    down.pushKV("helper_alive", false);
    check_err(down, "HELPER_DOWN");

    std::string code, err;
    BOOST_CHECK(!modelnet::HelperDownFail(false, code, err));
    BOOST_CHECK_EQUAL(code, "HELPER_DOWN");
    BOOST_CHECK(modelnet::HelperDownFail(true, code, err));

    modelnet::MemoryLimits lim;
    lim.host_physical_bytes = 64;
    BOOST_REQUIRE(modelnet::GlobalCapabilityBroker().Configure(lim, err));
    UniValue real_mem = EnsureReq(plan);
    UniValue got;
    BOOST_CHECK(!modelnet::EnsureCapability(cat, real_mem, got, code, err));
    BOOST_CHECK_EQUAL(code, "MEMORY_RESERVATION_FAILED");
    lim.host_physical_bytes = 1ull << 40;
    lim.host_pinned_bytes = 1ull << 30;
    BOOST_REQUIRE(modelnet::GlobalCapabilityBroker().Configure(lim, err));
}

BOOST_AUTO_TEST_CASE(JIT_API_05)
{
    BOOST_TEST_MESSAGE("JIT-API-05 Progress truth: files complete, warmup blocked");
    modelnet::ModelCatalog cat{m_path_root / "ensure-cat", 1 << 20};
    const auto plan = StorePlan();
    UniValue req = EnsureReq(plan);
    req.pushKV("block_warmup", true);
    UniValue got;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::EnsureCapability(cat, req, got, code, err), err);
    BOOST_CHECK(!got["progress"]["files_complete"].get_bool());
    BOOST_CHECK(!got["progress"]["canonical_bytes_verified"].get_bool());
    BOOST_CHECK_EQUAL(got["progress"]["implementation_status"].get_str(), std::string("IMPLEMENTED_LAB"));
    BOOST_CHECK(got["progress"]["runtime_ready"].isFalse());
    BOOST_CHECK(got["progress"]["first_useful_result"].isFalse());
    BOOST_CHECK_LT(got["progress"]["percent_ready"].getInt<int>(), 100);
    BOOST_CHECK_EQUAL(got["achieved"].get_str(),
                      std::string(modelnet::ReadinessTargetName(modelnet::ReadinessTarget::RUNTIME_LOADED)));
    BOOST_CHECK(got["smoke_passed"].isFalse());
    BOOST_CHECK(got["achieved"].get_str() !=
                std::string(modelnet::ReadinessTargetName(modelnet::ReadinessTarget::FIRST_USEFUL_RESULT)));
}

BOOST_AUTO_TEST_CASE(JIT_API_08)
{
    BOOST_TEST_MESSAGE("JIT-API-08 Ensure honesty: IMPLEMENTED_LAB fixture path, no canonical acquire claim");
    modelnet::ModelCatalog cat{m_path_root / "ensure-cat", 1 << 20};
    const auto plan = StorePlan();
    UniValue req = EnsureReq(plan);
    UniValue got;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::EnsureCapability(cat, req, got, code, err), err);

    // #168: EnsureCapability runs the local CPU fixture. It must not present that
    // as the plan's recipe digest having been acquired.
    BOOST_CHECK_EQUAL(got["implementation_status"].get_str(), std::string("IMPLEMENTED_LAB"));
    BOOST_CHECK(got["fixture_path"].isTrue());
    BOOST_CHECK(got["ready"].isFalse());
    BOOST_CHECK(got["fixture_runtime_ready"].get_bool());
    BOOST_CHECK(!got["progress"]["canonical_bytes_verified"].get_bool());
    BOOST_CHECK(!got["progress"]["files_complete"].get_bool());
    BOOST_CHECK(got["progress"]["fixture_bytes_materialized"].get_bool());
    BOOST_CHECK_EQUAL(got["progress"]["verified_representation"].get_str(), std::string("native-cpu-fixture"));
    BOOST_CHECK_LT(got["progress"]["percent_ready"].getInt<int>(), 100);

    // runtime_id label survives the honesty fields.
    BOOST_REQUIRE(got.exists("runtime_id"));
    BOOST_CHECK_EQUAL(got["runtime_id"].get_str(), std::string("synthetic-cpu-fixture"));

    // acquired_bytes is the fixture actually written, never the 4 MiB plan contract.
    BOOST_REQUIRE(got.exists("acquired_bytes"));
    const int64_t acquired = got["acquired_bytes"].getInt<int64_t>();
    const int64_t requested = got["requested_bytes"].getInt<int64_t>();
    BOOST_CHECK_GT(acquired, 0);
    BOOST_CHECK_EQUAL(requested, static_cast<int64_t>(plan.missing_bytes));
    BOOST_CHECK_GT(requested, acquired);
    BOOST_CHECK_EQUAL(got["progress"]["acquired_bytes"].getInt<int64_t>(), acquired);
    BOOST_CHECK_EQUAL(got["progress"]["requested_bytes"].getInt<int64_t>(), requested);
    BOOST_CHECK_EQUAL(got["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(NoSecrets(got));
}

BOOST_AUTO_TEST_CASE(JIT_API_06)
{
    BOOST_TEST_MESSAGE("JIT-API-06 Local events compact with explicit gaps");
    UniValue drain;
    BOOST_REQUIRE(modelnet::CompactCapabilityEvents(std::numeric_limits<int64_t>::max() / 4, drain));

    auto append = [](const char* kind) {
        UniValue e(UniValue::VOBJ);
        e.pushKV("kind", kind);
        BOOST_CHECK(modelnet::AppendCapabilityEvent(e));
    };
    append("plan");
    append("ensure");
    append("cancel");
    append("release");

    UniValue all;
    BOOST_REQUIRE(modelnet::CompactCapabilityEvents(0, all));
    BOOST_REQUIRE(all["events"].isArray());
    BOOST_REQUIRE_GE(all["events"].size(), 4);
    const int64_t last = all["next_cursor"].getInt<int64_t>();
    const int64_t mid = last - 2;
    BOOST_REQUIRE_GT(mid, 0);

    UniValue first;
    BOOST_REQUIRE(modelnet::CompactCapabilityEvents(mid, first));
    const int first_side = first["side_effects"].getInt<int>();
    BOOST_CHECK(first.exists("events"));
    UniValue replay;
    BOOST_REQUIRE(modelnet::CompactCapabilityEvents(mid, replay));
    BOOST_CHECK_EQUAL(replay["side_effects"].getInt<int>(), 0);
    BOOST_CHECK(replay["duplicate_side_effects"].isFalse());
    BOOST_CHECK_EQUAL(replay["events"].size(), first["events"].size());
    BOOST_CHECK(first_side >= 0);

    UniValue reconnect;
    BOOST_REQUIRE(modelnet::CompactCapabilityEvents(0, reconnect));
    if (reconnect["events"].size() > 0 && reconnect["events"][0].exists("seq")) {
        const int64_t first_seq = reconnect["events"][0]["seq"].getInt<int64_t>();
        if (first_seq > 1) BOOST_CHECK(reconnect["gap"].get_bool());
    }
    BOOST_CHECK_EQUAL(reconnect["automatic_spend_atoms"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_CASE(JIT_UPDATE_01)
{
    BOOST_TEST_MESSAGE("JIT-UPDATE-01 Prepare alongside active");
    UniValue req(UniValue::VOBJ);
    req.pushKV("lock_id", "active-old-lock");
    req.pushKV("digest", "aaa");
    req.pushKV("automatic_spend_atoms", 0);
    UniValue got;
    std::string code, err;
    BOOST_REQUIRE(modelnet::PlanCapabilityUpdate(req, got, code, err));
    BOOST_CHECK_EQUAL(got["old_lock"].get_str(), "active-old-lock");
    BOOST_CHECK(got["switch_ready"].isFalse());
    BOOST_CHECK(got["old_generation_stable"].get_bool());
    BOOST_CHECK(got["new_lock_prepared"].get_bool());
    BOOST_CHECK(got.exists("proposed_lock"));
    BOOST_CHECK_NE(got["proposed_lock"].get_str(), got["old_lock"].get_str());
    BOOST_CHECK_EQUAL(got["automatic_spend_atoms"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_CASE(JIT_UPDATE_02)
{
    BOOST_TEST_MESSAGE("JIT-UPDATE-02 Failed smoke is not activated");
    UniValue req(UniValue::VOBJ);
    req.pushKV("lock_id", "ready-old-gen");
    req.pushKV("smoke_failed", true);
    req.pushKV("smoke_passed", false);
    req.pushKV("digest", "new-fail");
    UniValue got;
    std::string code, err;
    BOOST_REQUIRE(modelnet::PlanCapabilityUpdate(req, got, code, err));
    BOOST_CHECK(got["switch_ready"].isFalse());
    BOOST_CHECK_EQUAL(got["active_lock"].get_str(), "ready-old-gen");
    BOOST_CHECK(got["old_generation_stable"].get_bool());
}

BOOST_AUTO_TEST_CASE(JIT_UPDATE_04)
{
    BOOST_TEST_MESSAGE("JIT-UPDATE-04 Rollback trust floor");
    std::string code, err;
    BOOST_CHECK(!modelnet::SoftwareTrustFloor("0.34.8", "0.33.2", code, err));
    BOOST_CHECK_EQUAL(code, "SOFTWARE_TRUST_REQUIRED");
    BOOST_CHECK(!modelnet::SoftwareTrustFloor("6", "4", code, err));
    BOOST_CHECK_EQUAL(code, "SOFTWARE_TRUST_REQUIRED");
    BOOST_CHECK(!modelnet::SoftwareTrustFloor("gen-b|client_min=6", "gen-a|client_min=4", code, err));
    BOOST_CHECK_EQUAL(code, "SOFTWARE_TRUST_REQUIRED");
    BOOST_CHECK(modelnet::SoftwareTrustFloor("0.34.8", "0.34.8", code, err));
    BOOST_CHECK(modelnet::SoftwareTrustFloor("6", "6", code, err));
    BOOST_CHECK(modelnet::SoftwareTrustFloor("gen-b|client_min=6", "gen-a|client_min=6", code, err));

    UniValue req(UniValue::VOBJ);
    req.pushKV("lock_id", "gen-b");
    req.pushKV("rollback", true);
    req.pushKV("current_client", "0.34.8");
    req.pushKV("rollback_client", "0.33.2");
    UniValue got;
    BOOST_CHECK(!modelnet::PlanCapabilityUpdate(req, got, code, err));
    BOOST_CHECK_EQUAL(code, "SOFTWARE_TRUST_REQUIRED");
    BOOST_CHECK_EQUAL(got["automatic_spend_atoms"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_CASE(JIT_UPDATE_07)
{
    BOOST_TEST_MESSAGE("JIT-UPDATE-07 Idempotent switch");
    UniValue req(UniValue::VOBJ);
    req.pushKV("lock_id", "idemp-old");
    req.pushKV("digest", "digest-aaa");
    req.pushKV("idempotency_key", "k1-ensure-update");
    req.pushKV("smoke_passed", true);
    UniValue a, b;
    std::string code, err;
    BOOST_REQUIRE(modelnet::PlanCapabilityUpdate(req, a, code, err));
    BOOST_REQUIRE(modelnet::PlanCapabilityUpdate(req, b, code, err));
    BOOST_CHECK(b["idempotent"].get_bool());
    BOOST_CHECK_EQUAL(a["proposed_lock"].get_str(), b["proposed_lock"].get_str());
    UniValue changed = req;
    changed.pushKV("digest", "digest-bbb");
    UniValue c;
    BOOST_CHECK(!modelnet::PlanCapabilityUpdate(changed, c, code, err));
    BOOST_CHECK_EQUAL(code, "IDEMPOTENCY_CONFLICT");
    BOOST_CHECK_EQUAL(c["error_code"].get_str(), "IDEMPOTENCY_CONFLICT");
}

BOOST_AUTO_TEST_CASE(JIT_ENSURE_IDEMPOTENCY_KEY_PAYLOAD)
{
    BOOST_TEST_MESSAGE("ensure: same key+payload replays; same key+different payload conflicts");
    modelnet::ModelCatalog cat{m_path_root / "ensure-idem", 1 << 20};
    const auto plan = StorePlan();
    UniValue req = EnsureReq(plan);
    req.pushKV("idempotency_key", "ensure-k-same");
    req.pushKV("runtime_id", "synthetic-cpu-fixture");
    UniValue first, replay;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::EnsureCapability(cat, req, first, code, err), err);
    BOOST_REQUIRE(first.exists("job_id") && first["job_id"].isStr());
    const std::string job = first["job_id"].get_str();
    BOOST_REQUIRE_MESSAGE(modelnet::EnsureCapability(cat, req, replay, code, err), err);
    BOOST_CHECK(replay["idempotent"].get_bool());
    BOOST_CHECK_EQUAL(replay["job_id"].get_str(), job);
    BOOST_CHECK_EQUAL(replay["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue other = req;
    other.pushKV("runtime_id", "synthetic-cpu-fixture-alt");
    UniValue conflict;
    BOOST_CHECK(!modelnet::EnsureCapability(cat, other, conflict, code, err));
    BOOST_CHECK_EQUAL(code, "IDEMPOTENCY_CONFLICT");
    BOOST_CHECK_EQUAL(conflict["error_code"].get_str(), "IDEMPOTENCY_CONFLICT");
    BOOST_CHECK(!conflict.exists("job_id"));
    BOOST_CHECK(!conflict["idempotent"].isTrue());
    BOOST_CHECK_EQUAL(conflict["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue nokey_a = EnsureReq(plan);
    UniValue nokey_b = EnsureReq(plan);
    UniValue a, b;
    BOOST_REQUIRE_MESSAGE(modelnet::EnsureCapability(cat, nokey_a, a, code, err), err);
    BOOST_REQUIRE_MESSAGE(modelnet::EnsureCapability(cat, nokey_b, b, code, err), err);
    BOOST_CHECK(a["job_id"].get_str() != b["job_id"].get_str());
}

BOOST_AUTO_TEST_CASE(hello_capability_objects_name_min_max)
{
    const UniValue caps = modelnet::HelloCapabilityArray();
    BOOST_REQUIRE(caps.isArray());
    BOOST_REQUIRE_GE(caps.size(), 1U);
    bool sub = false, pkg = false, gossip = false, core_v3 = false;
    for (const auto& c : caps.getValues()) {
        std::string n;
        BOOST_REQUIRE(modelnet::HelloCapabilityEntryName(c, n));
        BOOST_CHECK(c.isObject());
        BOOST_CHECK(!c.isStr());
        BOOST_CHECK(c.exists("min") && c["min"].isNum());
        BOOST_CHECK(c.exists("max") && c["max"].isNum());
        BOOST_CHECK_LE(c["min"].getInt<int>(), c["max"].getInt<int>());
        if (n == "SUBPIECE_V1") {
            sub = true;
            BOOST_CHECK_EQUAL(c["min"].getInt<int>(), 1);
            BOOST_CHECK_EQUAL(c["max"].getInt<int>(), 1);
        }
        if (n == "PACKAGE_V1") pkg = true;
        if (n == "METADATA_GOSSIP_V1") gossip = true;
        if (n == "BTXPKG_CORE_V3") {
            core_v3 = true;
            BOOST_CHECK_EQUAL(c["min"].getInt<int>(), 3);
            BOOST_CHECK_EQUAL(c["max"].getInt<int>(), 3);
        }
    }
    BOOST_CHECK(sub);
    BOOST_CHECK(pkg);
    BOOST_CHECK(gossip);
    BOOST_CHECK(core_v3);

    UniValue peer(UniValue::VOBJ);
    UniValue peer_caps(UniValue::VARR);
    UniValue sub_obj(UniValue::VOBJ);
    sub_obj.pushKV("name", "SUBPIECE_V1");
    sub_obj.pushKV("min", 1);
    sub_obj.pushKV("max", 1);
    peer_caps.push_back(sub_obj);
    UniValue unknown(UniValue::VOBJ);
    unknown.pushKV("name", "NOT_A_CAPABILITY");
    unknown.pushKV("min", 1);
    unknown.pushKV("max", 9);
    peer_caps.push_back(unknown);
    peer.pushKV("capabilities", peer_caps);
    const UniValue clamped = modelnet::IntersectHelloCapabilities(caps, peer);
    BOOST_REQUIRE(clamped.isArray());
    bool saw_sub = false;
    bool saw_unknown = false;
    for (const auto& c : clamped.getValues()) {
        std::string n;
        BOOST_REQUIRE(modelnet::HelloCapabilityEntryName(c, n));
        if (n == "SUBPIECE_V1") saw_sub = true;
        if (n == "NOT_A_CAPABILITY") saw_unknown = true;
    }
    BOOST_CHECK(saw_sub);
    BOOST_CHECK(!saw_unknown);

    UniValue hello(UniValue::VOBJ);
    hello.pushKV("capabilities", caps);
    BOOST_CHECK(modelnet::HelloHasCapability(hello, "FULL_FILE_STREAM_V1"));
    BOOST_CHECK(modelnet::HelloHasCapability(hello, "SUBPIECE_V1"));
    BOOST_CHECK(modelnet::HelloHasCapability(hello, "AGENT_HANDOFF_V1"));
    BOOST_CHECK(!modelnet::HelloHasCapability(hello, "NOT_A_CAPABILITY"));
    BOOST_CHECK(modelnet::IsFullFileStreamGet("GET", "/btx-model/2/files/aa/0"));
    BOOST_CHECK(!modelnet::IsFullFileStreamGet("POST", "/btx-model/2/hello"));
    size_t stream_cap = 0;
    std::string caperr;
    BOOST_REQUIRE(modelnet::FullFileStreamHttpBodyCap(true, 256 * 1024 + 1, stream_cap, caperr));
    BOOST_CHECK_GT(stream_cap, static_cast<size_t>(256 * 1024 + 8192));
    BOOST_CHECK(!modelnet::FullFileStreamHttpBodyCap(false, 1024, stream_cap, caperr));

    UniValue strings(UniValue::VARR);
    strings.push_back(std::string("SUBPIECE_V1"));
    strings.push_back(std::string("FULL_FILE_STREAM_V1"));
    UniValue hello_str(UniValue::VOBJ);
    hello_str.pushKV("capabilities", strings);
    BOOST_CHECK(modelnet::HelloHasCapability(hello_str, "SUBPIECE_V1"));
    BOOST_CHECK(modelnet::HelloHasCapability(hello_str, "FULL_FILE_STREAM_V1"));
}

BOOST_AUTO_TEST_CASE(JIT_JOURNEY_01)
{
    BOOST_TEST_MESSAGE("JIT-JOURNEY-01 Cold one-link CPU fixture");
    modelnet::ModelCatalog cat{m_path_root / "ensure-cat", 1 << 20};
    const auto plan = StorePlan();
    UniValue req = EnsureReq(plan);
    UniValue got;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::EnsureCapability(cat, req, got, code, err), err);
    BOOST_CHECK(got["smoke_passed"].get_bool());
    BOOST_CHECK_EQUAL(got["achieved"].get_str(),
                      std::string(modelnet::ReadinessTargetName(modelnet::ReadinessTarget::FIRST_USEFUL_RESULT)));
    BOOST_CHECK(OpaqueLease(got));
    BOOST_CHECK_EQUAL(got["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(got["second_downloader"].isFalse());

    UniValue ttc;
    BOOST_REQUIRE(modelnet::GetCapabilityTtcTrace(got["job_id"].get_str(), ttc, code, err));
    BOOST_CHECK(ttc["critical_path_not_sum"].get_bool());
    BOOST_CHECK_LT(ttc["wall_ms"].getInt<int64_t>(), ttc["sum_occupancy_ms"].getInt<int64_t>());
    BOOST_REQUIRE(ttc["stages"].isArray());
    BOOST_CHECK_EQUAL(ttc["stages"].size(), 7);
    BOOST_CHECK_EQUAL(ttc["automatic_spend_atoms"].getInt<int>(), 0);

    const auto probes = modelnet::ProbeRuntimeAdapters();
    BOOST_REQUIRE(!probes.empty());
    bool listed_llama = false, listed_vllm = false, listed_mlx = false;
    for (const auto& s : probes) {
        BOOST_CHECK_MESSAGE(!s.stub, s.runtime_id + " stub=true is dishonest");
        if (s.runtime_id == "llama.cpp") listed_llama = true;
        if (s.runtime_id == "vLLM") listed_vllm = true;
        if (s.runtime_id == "MLX") listed_mlx = true;
    }
    BOOST_CHECK(listed_llama);
    BOOST_CHECK(listed_vllm);
    BOOST_CHECK(listed_mlx);

    auto hw_ensure = [&](const char* runtime) {
        UniValue hreq = EnsureReq(plan);
        hreq.pushKV("runtime_id", runtime);
        UniValue tp(UniValue::VOBJ);
        tp.pushKV("adapter_abi", modelnet::RUNTIME_ADAPTER_ABI);
        hreq.pushKV("typed_params", tp);
        UniValue hgot;
        const bool ok = modelnet::EnsureCapability(cat, hreq, hgot, code, err);
        BOOST_CHECK(!ok);
        BOOST_CHECK(code == "HARDWARE_NOT_RUN" || code == "RUNTIME_NOT_INSTALLED" || code == "LIVE_RUNTIME_NOT_RUN" ||
                    code == "UNKNOWN_ADAPTER_PARAMETER");
        BOOST_TEST_MESSAGE(std::string("JIT-JOURNEY-01 ") + runtime + " NOT_RUN: " + code + " " + err);
        BOOST_CHECK(!hgot.exists("smoke_passed") || hgot["smoke_passed"].isFalse() || !ok);
    };
    hw_ensure("llama.cpp");
    UniValue vllm = EnsureReq(plan);
    vllm.pushKV("runtime_id", "vLLM");
    UniValue vtp(UniValue::VOBJ);
    vtp.pushKV("adapter_abi", modelnet::RUNTIME_ADAPTER_ABI);
    vtp.pushKV("backend", "CUDA");
    vllm.pushKV("typed_params", vtp);
    UniValue vgot;
    BOOST_CHECK(!modelnet::EnsureCapability(cat, vllm, vgot, code, err));
    BOOST_CHECK(code == "HARDWARE_NOT_RUN" || code == "RUNTIME_NOT_INSTALLED" || code == "LIVE_RUNTIME_NOT_RUN");
    BOOST_TEST_MESSAGE(std::string("JIT-JOURNEY-01 vLLM NOT_RUN: ") + code + " " + err);

    UniValue mlx = EnsureReq(plan);
    mlx.pushKV("runtime_id", "MLX");
    UniValue mtp(UniValue::VOBJ);
    mtp.pushKV("adapter_abi", modelnet::RUNTIME_ADAPTER_ABI);
    mtp.pushKV("backend", "METAL");
    mlx.pushKV("typed_params", mtp);
    UniValue mgot;
    BOOST_CHECK(!modelnet::EnsureCapability(cat, mlx, mgot, code, err));
    BOOST_CHECK(code == "HARDWARE_NOT_RUN" || code == "RUNTIME_NOT_INSTALLED" || code == "LIVE_RUNTIME_NOT_RUN");
    BOOST_TEST_MESSAGE(std::string("JIT-JOURNEY-01 MLX NOT_RUN: ") + code + " " + err);
}

BOOST_AUTO_TEST_CASE(JIT_JOURNEY_02)
{
    BOOST_TEST_MESSAGE("JIT-JOURNEY-02 Resident base, new specialization");
    modelnet::ModelCatalog cat{m_path_root / "ensure-cat", 1 << 20};
    std::string code, err;
    modelnet::Digest48 base{}, other{};
    BOOST_REQUIRE(modelnet::Digest48::FromHex(std::string(96, 'a'), base, err));
    BOOST_REQUIRE(modelnet::Digest48::FromHex(std::string(96, 'b'), other, err));
    BOOST_CHECK(!modelnet::AttachExactBaseAdapter(base, other, code, err));
    BOOST_CHECK_EQUAL(code, "ADAPTER_BASE_MISMATCH");
    BOOST_CHECK(modelnet::AttachExactBaseAdapter(base, base, code, err));
    BOOST_CHECK(modelnet::AttachExactBaseAdapter(base, base, code, err));
    modelnet::Digest48 composition{};
    BOOST_REQUIRE(modelnet::ComposeLoraOrder({std::string(96, 'c'), std::string(96, 'd')}, {"1", "1"}, composition, err));
    BOOST_CHECK(!composition.IsNull());

    const auto plan = StorePlan();
    UniValue req = EnsureReq(plan);
    req.pushKV("resident_base", true);
    req.pushKV("base_id", std::string(96, 'a'));
    req.pushKV("adapter_base_binding", std::string(96, 'a'));
    UniValue got;
    BOOST_REQUIRE_MESSAGE(modelnet::EnsureCapability(cat, req, got, code, err), err);
    BOOST_CHECK(got["second_downloader"].isFalse());
    BOOST_CHECK(got["used_global_transfer_credits"].get_bool());
    BOOST_CHECK(got["smoke_passed"].get_bool());
    BOOST_CHECK_EQUAL(got["automatic_spend_atoms"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_CASE(JIT_JOURNEY_04)
{
    BOOST_TEST_MESSAGE("JIT-JOURNEY-04 Sleep/wake after LoadTrustedRuntime");
    modelnet::ModelCatalog cat{m_path_root / "ensure-cat", 1 << 20};
    const auto plan = StorePlan();
    UniValue req = EnsureReq(plan);
    UniValue got;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::EnsureCapability(cat, req, got, code, err), err);
    const std::string lease = got["lease_id"].get_str();
    BOOST_REQUIRE(!lease.empty());

    UniValue sleep_st;
    BOOST_REQUIRE(modelnet::SleepRuntimePreserveWeights(lease, sleep_st, code, err));
    BOOST_CHECK(sleep_st["weights_preserved"].get_bool());
    BOOST_CHECK(sleep_st["kv_discarded"].get_bool());
    BOOST_CHECK(sleep_st["ready"].isFalse());
    BOOST_CHECK(sleep_st["premature_ready"].isFalse());

    modelnet::ReadyReceipt remapped;
    BOOST_CHECK(!modelnet::WakeRuntimeRemapOnly(lease, remapped, code, err));
    BOOST_CHECK_EQUAL(code, "PREMATURE_READY");

    modelnet::ReadyReceipt woke;
    code.clear();
    err.clear();
    BOOST_REQUIRE(modelnet::WakeRuntimeRebuildKv(lease, woke, code, err));
    BOOST_CHECK(woke.smoke_passed);
    BOOST_CHECK(woke.achieved == modelnet::ReadinessTarget::FIRST_USEFUL_RESULT);
    BOOST_CHECK(woke.json["kv_rebuilt"].get_bool());
    BOOST_CHECK(woke.json["ready"].get_bool());

    UniValue upd(UniValue::VOBJ);
    upd.pushKV("lock_id", got["generation"].get_str());
    upd.pushKV("digest", "wake-update");
    UniValue planned;
    BOOST_REQUIRE(modelnet::PlanCapabilityUpdate(upd, planned, code, err));
    BOOST_CHECK(planned["old_generation_stable"].get_bool());
}

BOOST_AUTO_TEST_CASE(JIT_JOURNEY_12)
{
    BOOST_TEST_MESSAGE("JIT-JOURNEY-12 Default cutover / helper-down / monetary invariance");
    modelnet::ModelCatalog cat{m_path_root / "ensure-cat", 1 << 20};
    std::string code, err;
    BOOST_CHECK(!modelnet::HelperDownFail(false, code, err));
    BOOST_CHECK_EQUAL(code, "HELPER_DOWN");
    BOOST_CHECK(!modelnet::RejectLegacyModelHandshake(2, code, err));
    BOOST_CHECK_EQUAL(code, "UNSUPPORTED_CORE_VERSION");
    BOOST_CHECK(modelnet::RejectLegacyModelHandshake(3, code, err));

    UniValue oldm(UniValue::VOBJ);
    oldm.pushKV("phase", "crash-mid-journal");
    oldm.pushKV("verified_representation", std::string(96, 'c'));
    UniValue neu;
    BOOST_REQUIRE(modelnet::MigratePriorPackageState(oldm, neu, code, err));
    BOOST_CHECK(neu["resumed"].get_bool());
    BOOST_CHECK_EQUAL(neu["automatic_spend_atoms"].getInt<int>(), 0);

    const auto plan = StorePlan();
    UniValue spend = EnsureReq(plan);
    spend.pushKV("automatic_spend_atoms", 1);
    UniValue got;
    BOOST_CHECK(!modelnet::EnsureCapability(cat, spend, got, code, err));
    BOOST_CHECK_EQUAL(code, "PAID_PATH_FORBIDDEN");

    UniValue down = EnsureReq(plan);
    down.pushKV("helper_alive", false);
    BOOST_CHECK(!modelnet::EnsureCapability(cat, down, got, code, err));
    BOOST_CHECK_EQUAL(code, "HELPER_DOWN");

    UniValue ok = EnsureReq(plan);
    BOOST_REQUIRE_MESSAGE(modelnet::EnsureCapability(cat, ok, got, code, err), err);
    BOOST_CHECK_EQUAL(got["automatic_spend_atoms"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_CASE(remaining_capability_rpc_surface)
{
    modelnet::ModelCatalog cat{m_path_root / "cap-rpc-surface", 1 << 20};
    std::string code, err;

    auto rpc = [](const std::string& method, const UniValue& params) {
        UniValue req(UniValue::VOBJ);
        req.pushKV("method", method);
        req.pushKV("params", params);
        return req;
    };

    UniValue resolve_in(UniValue::VOBJ);
    resolve_in.pushKV("recipe", RecipeJson());
    resolve_in.pushKV("grant", GrantJson());
    UniValue resolved;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc("resolvebtxcapability", resolve_in), resolved, code, err), err);
    BOOST_REQUIRE(resolved["candidates"].isArray());
    BOOST_REQUIRE_GE(resolved["candidates"].size(), 1U);
    BOOST_CHECK_EQUAL(resolved["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue lock_in(UniValue::VOBJ);
    lock_in.pushKV("recipe_id", std::string(96, 'a'));
    UniValue exported;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc("exportbtxlock", lock_in), exported, code, err), err);
    BOOST_CHECK(exported.exists("hex") || exported.exists("lock_id"));
    BOOST_CHECK_EQUAL(exported["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue imported;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc("importbtxlock", lock_in), imported, code, err), err);
    BOOST_CHECK(imported["imported"].get_bool());
    BOOST_CHECK_EQUAL(imported["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue map_in(UniValue::VOBJ);
    map_in.pushKV("hex", "02000000000000007b7d");
    UniValue mapped;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc("inspectbtxtensormap", map_in), mapped, code, err), err);
    BOOST_CHECK(mapped.exists("map_id") || mapped.exists("tensors"));
    BOOST_CHECK_EQUAL(mapped["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue switched;
    UniValue sw(UniValue::VOBJ);
    sw.pushKV("old_lock", "old");
    sw.pushKV("new_lock", "new");
    sw.pushKV("phase", "commit");
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc("switchbtxcapability", sw), switched, code, err), err);
    BOOST_CHECK(switched["switched"].get_bool());
    BOOST_CHECK_EQUAL(switched["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue caps;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc("getbtxruntimecapabilities", UniValue(UniValue::VOBJ)), caps, code, err), err);
    BOOST_CHECK(caps["public_runtime_rpc"].isFalse());
    BOOST_CHECK_EQUAL(caps["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue plan_in(UniValue::VOBJ);
    plan_in.pushKV("recipe", RecipeJson());
    plan_in.pushKV("grant", GrantJson());
    UniValue planned;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc("planbtxcapability", plan_in), planned, code, err), err);
    BOOST_REQUIRE(planned.exists("plan_id") && planned["plan_id"].isStr());
    BOOST_CHECK_EQUAL(planned["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue ensure_in(UniValue::VOBJ);
    ensure_in.pushKV("plan_id", planned["plan_id"].get_str());
    ensure_in.pushKV("grant", GrantJson());
    UniValue ensured;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc("ensurebtxcapability", ensure_in), ensured, code, err), err);
    BOOST_REQUIRE(ensured.exists("lease_id") && ensured["lease_id"].isStr());
    BOOST_CHECK_EQUAL(ensured["automatic_spend_atoms"].getInt<int>(), 0);
    const std::string lease = ensured["lease_id"].get_str();
    const std::string job = ensured.exists("job_id") && ensured["job_id"].isStr() ? ensured["job_id"].get_str() : "";

    UniValue got;
    UniValue get_in(UniValue::VOBJ);
    if (!job.empty()) get_in.pushKV("job_id", job);
    else get_in.pushKV("lease_id", lease);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc("getbtxcapability", get_in), got, code, err), err);
    BOOST_CHECK_EQUAL(got["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue slept;
    UniValue sleep_in(UniValue::VOBJ);
    sleep_in.pushKV("lease_id", lease);
    sleep_in.pushKV("grant", GrantJson());
    const bool sleep_ok = modelnet::DispatchHelperRpc(cat, rpc("sleepbtxcapability", sleep_in), slept, code, err);
    if (sleep_ok) {
        BOOST_CHECK(!slept.exists("ready") || slept["ready"].isFalse());
        BOOST_CHECK_EQUAL(slept["automatic_spend_atoms"].getInt<int>(), 0);
    } else {
        BOOST_CHECK(code != "METHOD_NOT_FOUND");
        BOOST_CHECK(!slept.exists("ready") || slept["ready"].isFalse());
    }

    UniValue woke;
    UniValue wake_in(UniValue::VOBJ);
    wake_in.pushKV("lease_id", lease);
    wake_in.pushKV("grant", GrantJson());
    const bool wake_ok = modelnet::DispatchHelperRpc(cat, rpc("wakebtxcapability", wake_in), woke, code, err);
    if (wake_ok) {
        BOOST_CHECK(woke["discarded_kv_rebuilt"].isTrue() || woke["ready"].isTrue());
        BOOST_CHECK_EQUAL(woke["automatic_spend_atoms"].getInt<int>(), 0);
    } else {
        BOOST_CHECK(code != "METHOD_NOT_FOUND");
    }

    UniValue events;
    UniValue ev_in(UniValue::VOBJ);
    ev_in.pushKV("cursor", 0);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc("getbtxcapabilityevents", ev_in), events, code, err), err);
    BOOST_REQUIRE(events["events"].isArray());
    BOOST_CHECK_EQUAL(events["automatic_spend_atoms"].getInt<int>(), 0);

    if (!job.empty()) {
        UniValue ttc;
        UniValue ttc_in(UniValue::VOBJ);
        ttc_in.pushKV("job_id", job);
        BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc("getbtxttctrace", ttc_in), ttc, code, err), err);
        BOOST_CHECK(ttc["critical_path_not_sum"].isTrue());
        BOOST_CHECK_EQUAL(ttc["automatic_spend_atoms"].getInt<int>(), 0);
    }

    UniValue residency;
    UniValue res_in(UniValue::VOBJ);
    res_in.pushKV("grant", GrantJson());
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc("getbtxresidency", res_in), residency, code, err), err);
    BOOST_CHECK(residency["no_public_pointers"].isTrue());
    BOOST_CHECK_EQUAL(residency["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue prefetch;
    UniValue pref_in(UniValue::VOBJ);
    pref_in.pushKV("grant", GrantJson());
    pref_in.pushKV("recipe_id", "base");
    pref_in.pushKV("bytes", 1);
    const bool pref_ok = modelnet::DispatchHelperRpc(cat, rpc("prefetchbtxcapability", pref_in), prefetch, code, err);
    if (pref_ok) {
        BOOST_CHECK_EQUAL(prefetch["automatic_spend_atoms"].getInt<int>(), 0);
    } else {
        BOOST_CHECK(code == "BUDGET_EXCEEDED" || code == "CACHE_MISS" || code == "INVALID_PARAMETER" ||
                    code.find("GRANT") != std::string::npos);
    }

    UniValue upd;
    UniValue upd_in(UniValue::VOBJ);
    upd_in.pushKV("lease_id", lease);
    upd_in.pushKV("grant", GrantJson());
    const bool upd_ok = modelnet::DispatchHelperRpc(cat, rpc("planbtxcapabilityupdate", upd_in), upd, code, err);
    if (upd_ok) {
        BOOST_CHECK_EQUAL(upd["automatic_spend_atoms"].getInt<int>(), 0);
    } else {
        BOOST_CHECK(code != "METHOD_NOT_FOUND");
    }

    if (!job.empty()) {
        UniValue cancelled;
        UniValue can_in(UniValue::VOBJ);
        can_in.pushKV("job_id", job);
        can_in.pushKV("still_inflight", true);
        BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc("cancelbtxcapability", can_in), cancelled, code, err), err);
        BOOST_CHECK(cancelled["cancelled"].isTrue());
        BOOST_CHECK_EQUAL(cancelled["automatic_spend_atoms"].getInt<int>(), 0);
    }

    UniValue released;
    UniValue rel_in(UniValue::VOBJ);
    rel_in.pushKV("lease_id", lease);
    const bool rel_ok = modelnet::DispatchHelperRpc(cat, rpc("releasebtxcapability", rel_in), released, code, err);
    if (rel_ok) {
        BOOST_CHECK_EQUAL(released["automatic_spend_atoms"].getInt<int>(), 0);
    } else {
        BOOST_CHECK_EQUAL(code, "LEASE_HOLD");
    }
}

BOOST_AUTO_TEST_SUITE_END()
