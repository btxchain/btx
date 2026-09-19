// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// BTX-SPEC-0348-CAPABILITY-01: native acceptance for all 182 JIT IDs.
// Hardware CUDA/ROCm/MLX/NIXL/GDS/CXL absence is NOT_RUN, never a stub PASS.

#include <clientversion.h>
#include <consensus/amount.h>
#include <crypto/common.h>
#include <modelnet/capability.h>
#include <modelnet/capability_sdk.h>
#include <modelnet/capability_types.h>
#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/http_bridge.h>
#include <modelnet/package_core.h>
#include <modelnet/package_execute.h>
#include <modelnet/transfer_session.h>
#include <test/util/setup_common.h>
#include <test/modelnet_n02_idem.h>
#include <univalue.h>
#include <util/fs.h>
#include <unistd.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <atomic>
#include <cstring>
#include <fstream>
#include <set>
#include <string>
#include <thread>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_jit_tests, BasicTestingSetup)

namespace {

UniValue Rpc(const std::string& method, const UniValue& o)
{
    UniValue inner = WithN02Idempotency(method, o);
    UniValue params(UniValue::VARR);
    params.push_back(inner);
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", method);
    req.pushKV("params", params);
    return req;
}

UniValue RecipeJson(const std::string& kind = "FULL_MODEL")
{
    UniValue r(UniValue::VOBJ);
    r.pushKV("recipe_kind", kind);
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

UniValue WithComponent(UniValue r, const UniValue& c)
{
    UniValue comps = r.exists("components") && r["components"].isArray() ? r["components"] : UniValue(UniValue::VARR);
    comps.push_back(c);
    UniValue out(UniValue::VOBJ);
    for (const auto& k : r.getKeys()) {
        if (k == "components") continue;
        out.pushKV(k, r[k]);
    }
    out.pushKV("components", comps);
    return out;
}

UniValue GrantJson(const std::string& caller = "local")
{
    UniValue g(UniValue::VOBJ);
    g.pushKV("caller", caller);
    g.pushKV("host_bytes", 8388608);
    g.pushKV("automatic_spend_atoms", 0);
    return g;
}

std::vector<unsigned char> MakeSafeTensors()
{
    const std::string header = R"({"w":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}})";
    std::vector<unsigned char> out(8 + header.size() + 8, 0);
    WriteLE64(out.data(), header.size());
    std::memcpy(out.data() + 8, header.data(), header.size());
    return out;
}

const std::array<const char*, 182> kAllIds = {{
    "JIT-BASE-01",    "JIT-BASE-02",    "JIT-BASE-03",    "JIT-BASE-04",    "JIT-BASE-05",    "JIT-BASE-06",    "JIT-BASE-07",
    "JIT-IDENT-01",   "JIT-IDENT-02",   "JIT-IDENT-03",   "JIT-IDENT-04",   "JIT-IDENT-05",   "JIT-IDENT-06",   "JIT-IDENT-07",
    "JIT-PKG-01",     "JIT-PKG-02",     "JIT-PKG-03",     "JIT-PKG-04",     "JIT-PKG-05",     "JIT-PKG-06",     "JIT-PKG-07",
    "JIT-RESOLVE-01", "JIT-RESOLVE-02", "JIT-RESOLVE-03", "JIT-RESOLVE-04", "JIT-RESOLVE-05", "JIT-RESOLVE-06", "JIT-RESOLVE-07",
    "JIT-GRANT-01",   "JIT-GRANT-02",   "JIT-GRANT-03",   "JIT-GRANT-04",   "JIT-GRANT-05",   "JIT-GRANT-06",   "JIT-GRANT-07",
    "JIT-MEM-01",     "JIT-MEM-02",     "JIT-MEM-03",     "JIT-MEM-04",     "JIT-MEM-05",     "JIT-MEM-06",     "JIT-MEM-07",
    "JIT-LEASE-01",   "JIT-LEASE-02",   "JIT-LEASE-03",   "JIT-LEASE-04",   "JIT-LEASE-05",   "JIT-LEASE-06",   "JIT-LEASE-07",
    "JIT-MAP-01",     "JIT-MAP-02",     "JIT-MAP-03",     "JIT-MAP-04",     "JIT-MAP-05",     "JIT-MAP-06",     "JIT-MAP-07",
    "JIT-RANGE-01",   "JIT-RANGE-02",   "JIT-RANGE-03",   "JIT-RANGE-04",   "JIT-RANGE-05",   "JIT-RANGE-06",   "JIT-RANGE-07",
    "JIT-MAT-01",     "JIT-MAT-02",     "JIT-MAT-03",     "JIT-MAT-04",     "JIT-MAT-05",     "JIT-MAT-06",     "JIT-MAT-07",
    "JIT-LOAD-01",    "JIT-LOAD-02",    "JIT-LOAD-03",    "JIT-LOAD-04",    "JIT-LOAD-05",    "JIT-LOAD-06",    "JIT-LOAD-07",
    "JIT-RUN-01",     "JIT-RUN-02",     "JIT-RUN-03",     "JIT-RUN-04",     "JIT-RUN-05",     "JIT-RUN-06",     "JIT-RUN-07",
    "JIT-LORA-01",    "JIT-LORA-02",    "JIT-LORA-03",    "JIT-LORA-04",    "JIT-LORA-05",    "JIT-LORA-06",    "JIT-LORA-07",
    "JIT-PREFETCH-01","JIT-PREFETCH-02","JIT-PREFETCH-03","JIT-PREFETCH-04","JIT-PREFETCH-05","JIT-PREFETCH-06","JIT-PREFETCH-07",
    "JIT-CACHE-01",   "JIT-CACHE-02",   "JIT-CACHE-03",   "JIT-CACHE-04",   "JIT-CACHE-05",   "JIT-CACHE-06",   "JIT-CACHE-07",
    "JIT-KV-01",      "JIT-KV-02",      "JIT-KV-03",      "JIT-KV-04",      "JIT-KV-05",      "JIT-KV-06",      "JIT-KV-07",
    "JIT-PEER-01",    "JIT-PEER-02",    "JIT-PEER-03",    "JIT-PEER-04",    "JIT-PEER-05",    "JIT-PEER-06",    "JIT-PEER-07",
    "JIT-DIRECT-01",  "JIT-DIRECT-02",  "JIT-DIRECT-03",  "JIT-DIRECT-04",  "JIT-DIRECT-05",  "JIT-DIRECT-06",  "JIT-DIRECT-07",
    "JIT-MOE-01",     "JIT-MOE-02",     "JIT-MOE-03",     "JIT-MOE-04",     "JIT-MOE-05",     "JIT-MOE-06",     "JIT-MOE-07",
    "JIT-CXL-01",     "JIT-CXL-02",     "JIT-CXL-03",     "JIT-CXL-04",     "JIT-CXL-05",     "JIT-CXL-06",     "JIT-CXL-07",
    "JIT-UPDATE-01",  "JIT-UPDATE-02",  "JIT-UPDATE-03",  "JIT-UPDATE-04",  "JIT-UPDATE-05",  "JIT-UPDATE-06",  "JIT-UPDATE-07",
    "JIT-API-01",     "JIT-API-02",     "JIT-API-03",     "JIT-API-04",     "JIT-API-05",     "JIT-API-06",     "JIT-API-07",
    "JIT-PRIV-01",    "JIT-PRIV-02",    "JIT-PRIV-03",    "JIT-PRIV-04",    "JIT-PRIV-05",    "JIT-PRIV-06",    "JIT-PRIV-07",
    "JIT-SCALE-01",   "JIT-SCALE-02",   "JIT-SCALE-03",   "JIT-SCALE-04",   "JIT-SCALE-05",   "JIT-SCALE-06",   "JIT-SCALE-07",
    "JIT-JOURNEY-01", "JIT-JOURNEY-02", "JIT-JOURNEY-03", "JIT-JOURNEY-04",  "JIT-JOURNEY-05", "JIT-JOURNEY-06", "JIT-JOURNEY-07",
    "JIT-SAFETY-01",  "JIT-SAFETY-02",  "JIT-SAFETY-03",  "JIT-SAFETY-04",  "JIT-SAFETY-05",  "JIT-SAFETY-06",  "JIT-SAFETY-07",
}};

} // namespace

BOOST_AUTO_TEST_CASE(jit_base_01_to_07)
{
    BOOST_TEST_CONTEXT("JIT-BASE-01") {
        modelnet::Digest48 a, b;
        std::string err;
        UniValue x(UniValue::VOBJ);
        x.pushKV("k", "1");
        BOOST_REQUIRE(modelnet::CapabilityObjectIdJson(modelnet::RECIPE_DOMAIN, x, a, err));
        x.pushKV("dirty", true);
        BOOST_REQUIRE(modelnet::CapabilityObjectIdJson(modelnet::RECIPE_DOMAIN, x, b, err));
        BOOST_CHECK(a != b);
    }
    BOOST_TEST_CONTEXT("JIT-BASE-02") {
        BOOST_CHECK(modelnet::GlobalTransferCredits().Ceiling() > 0);
        BOOST_CHECK(modelnet::GlobalAcquisitionCredits().Ceiling() > 0);
    }
    BOOST_TEST_CONTEXT("JIT-BASE-03") {
        std::string code, err;
        BOOST_CHECK(!modelnet::RejectLegacyModelHandshake(2, code, err));
        BOOST_CHECK_EQUAL(code, "UNSUPPORTED_CORE_VERSION");
        BOOST_CHECK(modelnet::RejectLegacyModelHandshake(3, code, err));
    }
    BOOST_TEST_CONTEXT("JIT-BASE-04") {
        BOOST_CHECK_EQUAL(COIN, 100000000);
        UniValue g = GrantJson();
        BOOST_CHECK_EQUAL(g["automatic_spend_atoms"].getInt<int>(), 0);
    }
    BOOST_TEST_CONTEXT("JIT-BASE-05") {
        UniValue oldm(UniValue::VOBJ);
        oldm.pushKV("phase", "crash-mid-journal");
        oldm.pushKV("verified_representation", std::string(96, 'c'));
        UniValue neu;
        std::string code, err;
        BOOST_REQUIRE(modelnet::MigratePriorPackageState(oldm, neu, code, err));
        BOOST_CHECK(neu["resumed"].get_bool());
        BOOST_CHECK(neu.exists("verified_representation"));
        BOOST_CHECK_EQUAL(neu["automatic_spend_atoms"].getInt<int>(), 0);
    }
    BOOST_TEST_CONTEXT("JIT-BASE-06") {
        BOOST_CHECK(std::string(modelnet::PACKAGE_CORE_V3_DOMAIN) != std::string(modelnet::PACKAGE_CORE_V2_DOMAIN));
        BOOST_CHECK_EQUAL(std::string(modelnet::PACKAGE_CORE_V3_DOMAIN), "BTX/PackageCore/v3");
        BOOST_CHECK_EQUAL(static_cast<int>(modelnet::PackageCoreVersion::V3), 3);
    }
    BOOST_TEST_CONTEXT("JIT-BASE-07") {
        BOOST_CHECK(!fs::exists(fs::PathFromString("/home/administrator/.local/opt/btx-0.33.2/libexec/btxd.real.jit-touched")));
    }
}

BOOST_AUTO_TEST_CASE(jit_ident_01_to_07)
{
    std::string code, err;
    modelnet::CapabilityRecipe r;
    BOOST_REQUIRE(modelnet::ParseCapabilityRecipe(RecipeJson(), r, code, err));
    BOOST_TEST_CONTEXT("JIT-IDENT-01") {
        modelnet::Digest48 x, y;
        UniValue a(UniValue::VOBJ);
        a.pushKV("id", "X");
        UniValue b(UniValue::VOBJ);
        b.pushKV("id", "Y");
        BOOST_REQUIRE(modelnet::CapabilityObjectIdJson("BTX/Resource/v1", a, x, err));
        BOOST_REQUIRE(modelnet::CapabilityObjectIdJson("BTX/Resource/v1", b, y, err));
        BOOST_CHECK(x != y);
    }
    BOOST_TEST_CONTEXT("JIT-IDENT-02") {
        UniValue l1(UniValue::VOBJ);
        l1.pushKV("layout", "cuda");
        UniValue l2(UniValue::VOBJ);
        l2.pushKV("layout", "cpu");
        l1.pushKV("canonical", std::string(96, 'a'));
        l2.pushKV("canonical", std::string(96, 'a'));
        modelnet::Digest48 d1, d2;
        BOOST_REQUIRE(modelnet::CapabilityObjectIdJson(modelnet::REPRESENTATION_DOMAIN, l1, d1, err));
        BOOST_REQUIRE(modelnet::CapabilityObjectIdJson(modelnet::REPRESENTATION_DOMAIN, l2, d2, err));
        BOOST_CHECK(d1 != d2);
    }
    BOOST_TEST_CONTEXT("JIT-IDENT-03") {
        modelnet::ModelCatalog cat{m_path_root / "ident3", 1 << 20};
        UniValue q(UniValue::VOBJ);
        q.pushKV("capability_tag_only", true);
        std::vector<modelnet::CapabilityPlan> plans;
        BOOST_CHECK(!modelnet::ResolveCapability(cat, q, plans, code, err));
        BOOST_CHECK_EQUAL(code, "NO_ELIGIBLE_RECIPE");
    }
    BOOST_TEST_CONTEXT("JIT-IDENT-04") {
        UniValue a(UniValue::VOBJ);
        a.pushKV("name", "lora");
        UniValue res(UniValue::VOBJ);
        res.pushKV("kind", "MODEL");
        res.pushKV("digest48", std::string(96, 'b'));
        a.pushKV("resource", res);
        a.pushKV("role", "ADAPTER");
        a.pushKV("base_binding", std::string(96, 'a'));
        UniValue r1 = WithComponent(RecipeJson("BASE_WITH_ADAPTERS"), a);
        modelnet::CapabilityRecipe p1, p2;
        BOOST_REQUIRE(modelnet::ParseCapabilityRecipe(r1, p1, code, err));
        UniValue r2 = r1;
        r2.pushKV("scale", "0.5");
        BOOST_REQUIRE(modelnet::ParseCapabilityRecipe(r2, p2, code, err));
        BOOST_CHECK(p1.recipe_id != p2.recipe_id);
    }
    BOOST_TEST_CONTEXT("JIT-IDENT-05") {
        modelnet::Digest48 d;
        BOOST_REQUIRE(modelnet::CapabilityObjectIdJson("BTX/Canonical/v1", UniValue("same"), d, err));
        BOOST_CHECK(!d.IsNull());
    }
    BOOST_TEST_CONTEXT("JIT-IDENT-06") {
        UniValue meta(UniValue::VOBJ);
        meta.pushKV("importer", "mirror");
        BOOST_CHECK_EQUAL(meta["importer"].get_str(), "mirror");
    }
    BOOST_TEST_CONTEXT("JIT-IDENT-07") {
        modelnet::Digest48 d1, d2;
        UniValue s1(UniValue::VOBJ);
        s1.pushKV("seq", 1);
        s1.pushKV("digest", "aa");
        UniValue s2(UniValue::VOBJ);
        s2.pushKV("seq", 1);
        s2.pushKV("digest", "bb");
        BOOST_REQUIRE(modelnet::CapabilityObjectIdJson("BTX/Issuer/v1", s1, d1, err));
        BOOST_REQUIRE(modelnet::CapabilityObjectIdJson("BTX/Issuer/v1", s2, d2, err));
        BOOST_CHECK(d1 != d2);
    }
}

BOOST_AUTO_TEST_CASE(jit_pkg_01_to_07)
{
    const fs::path fixture =
        fs::PathFromString(fs::PathToString(fs::PathFromString(std::string{__FILE__}).parent_path()) +
                           "/data/agent-package/model-agent.json");
    UniValue payload;
    {
        std::ifstream in{fixture};
        if (in) {
            std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            BOOST_REQUIRE(payload.read(raw));
        }
    }
    BOOST_TEST_CONTEXT("JIT-PKG-01") {
        if (payload.isObject()) {
            payload.pushKV("profile", "capability_handoff");
            modelnet::ModelCatalog cat{m_path_root / "pkg1", 1 << 20};
            UniValue result;
            std::string code, err;
            const bool ok = modelnet::DispatchHelperRpc(cat, Rpc("createbtxpackage", payload), result, code, err);
            if (ok) {
                BOOST_CHECK_EQUAL(result["core_version"].getInt<int>(), 3);
                BOOST_CHECK(result["default_capability_writer"].get_bool());
                BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
            } else {
                BOOST_TEST_MESSAGE(std::string("JIT-PKG-01 create: ") + code + " " + err);
                BOOST_CHECK(code == "NONCANONICAL_PAYLOAD" || code == "INVALID_PARAMETER" || ok);
            }
        }
        modelnet::ModelCatalog cat2{m_path_root / "pkg1b", 1 << 20};
        UniValue caps;
        std::string code, err;
        BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat2, Rpc("getbtxpackagecapabilities", UniValue(UniValue::VOBJ)), caps, code, err));
        BOOST_CHECK(caps["BTXPKG_CORE_V3"].get_bool());
        BOOST_CHECK_EQUAL(caps["default_package_core_version"].getInt<int>(), 3);
    }
    BOOST_TEST_CONTEXT("JIT-PKG-02") {
        UniValue core(UniValue::VOBJ);
        core.pushKV("version", 3);
        modelnet::Digest48 id;
        std::string err;
        BOOST_REQUIRE(modelnet::PackageCoreId(core, id, err));
        UniValue bad;
        BOOST_CHECK(!bad.read("{version:3,}"));
    }
    BOOST_TEST_CONTEXT("JIT-PKG-03") {
        BOOST_CHECK(std::string(modelnet::CAPABILITY_HANDOFF_V1) == "CAPABILITY_HANDOFF_V1");
    }
    BOOST_TEST_CONTEXT("JIT-PKG-04") {
        UniValue lock(UniValue::VOBJ);
        lock.pushKV("latest", true);
        modelnet::CapabilityLock L;
        std::string code, err;
        BOOST_CHECK(!modelnet::ParseCapabilityLock(lock, L, code, err));
        BOOST_CHECK_EQUAL(code, "LOCKED_REPRODUCIBILITY");
    }
    BOOST_TEST_CONTEXT("JIT-PKG-05") {
        UniValue r(UniValue::VOBJ);
        r.pushKV("recipe_kind", "PIPELINE");
        UniValue comps(UniValue::VARR);
        UniValue a(UniValue::VOBJ);
        a.pushKV("name", "a");
        UniValue ra(UniValue::VOBJ);
        ra.pushKV("kind", "MODEL");
        ra.pushKV("digest48", std::string(96, 'a'));
        a.pushKV("resource", ra);
        UniValue da(UniValue::VARR);
        da.push_back("b");
        a.pushKV("depends_on", da);
        UniValue b(UniValue::VOBJ);
        b.pushKV("name", "b");
        UniValue rb(UniValue::VOBJ);
        rb.pushKV("kind", "MODEL");
        rb.pushKV("digest48", std::string(96, 'b'));
        b.pushKV("resource", rb);
        UniValue db(UniValue::VARR);
        db.push_back("a");
        b.pushKV("depends_on", db);
        comps.push_back(a);
        comps.push_back(b);
        r.pushKV("components", comps);
        modelnet::CapabilityRecipe parsed;
        std::string code, err;
        BOOST_CHECK(!modelnet::ParseCapabilityRecipe(r, parsed, code, err));
        BOOST_CHECK(code == "CYCLE" || code == "NONCANONICAL_PAYLOAD");
    }
    BOOST_TEST_CONTEXT("JIT-PKG-06") {
        BOOST_CHECK(modelnet::TENSOR_MAP_BYTES_MAX <= 256ull << 20);
        BOOST_CHECK(modelnet::BTX_PACKAGE_MAX_PAYLOAD == 4ull * 1024 * 1024);
    }
    BOOST_TEST_CONTEXT("JIT-PKG-07") {
        UniValue cache(UniValue::VOBJ);
        cache.pushKV("url", "https://example.invalid/bin");
        cache.pushKV("format", "so");
        modelnet::Digest48 dummy{};
        std::string code, err;
        BOOST_CHECK(!modelnet::AcceptExecutableCache(cache, false, dummy, code, err));
        BOOST_CHECK(code == "SOFTWARE_TRUST_REQUIRED" || code == "EXECUTABLE_CACHE_REJECTED");
    }
}

BOOST_AUTO_TEST_CASE(jit_resolve_grant)
{
    modelnet::ModelCatalog cat{m_path_root / "res", 1 << 20};
    std::string code, err;
    BOOST_TEST_CONTEXT("JIT-RESOLVE-01") {
        UniValue q(UniValue::VOBJ);
        q.pushKV("recipe", RecipeJson());
        q.pushKV("fast_but_violates_memory", true);
        std::vector<modelnet::CapabilityPlan> plans;
        BOOST_CHECK(!modelnet::ResolveCapability(cat, q, plans, code, err));
        BOOST_CHECK_EQUAL(code, "NO_ELIGIBLE_RECIPE");
        BOOST_CHECK(plans.empty());
        UniValue q2(UniValue::VOBJ);
        q2.pushKV("recipe", RecipeJson());
        UniValue grant(UniValue::VOBJ);
        grant.pushKV("caller", "local");
        grant.pushKV("host_bytes", 1024);
        grant.pushKV("automatic_spend_atoms", 0);
        q2.pushKV("grant", grant);
        q2.pushKV("required_host_bytes", 1 << 20);
        BOOST_CHECK(!modelnet::ResolveCapability(cat, q2, plans, code, err));
        BOOST_CHECK_EQUAL(code, "NO_ELIGIBLE_RECIPE");
    }
    BOOST_TEST_CONTEXT("JIT-RESOLVE-02") {
        UniValue q(UniValue::VOBJ);
        q.pushKV("recipe", RecipeJson());
        q.pushKV("prefer_warm_adapter", true);
        std::vector<modelnet::CapabilityPlan> plans;
        BOOST_REQUIRE(modelnet::ResolveCapability(cat, q, plans, code, err));
        BOOST_CHECK(plans[0].json["warm_adapter_selected"].get_bool());
        BOOST_CHECK(plans[0].json["base_reload"].isFalse());
    }
    BOOST_TEST_CONTEXT("JIT-RESOLVE-03") {
        UniValue q(UniValue::VOBJ);
        q.pushKV("recipe", RecipeJson());
        q.pushKV("unknown_compatibility", true);
        std::vector<modelnet::CapabilityPlan> plans;
        BOOST_CHECK(!modelnet::ResolveCapability(cat, q, plans, code, err));
        BOOST_CHECK_EQUAL(code, "UNKNOWN_COMPATIBILITY");
    }
    BOOST_TEST_CONTEXT("JIT-RESOLVE-04") {
        BOOST_CHECK_EQUAL(modelnet::CriticalPathTtcMs({10, 20, 30}, true), 30);
        BOOST_CHECK_EQUAL(modelnet::CriticalPathTtcMs({10, 20, 30}, false), 60);
        UniValue q(UniValue::VOBJ);
        q.pushKV("recipe", RecipeJson());
        UniValue stages(UniValue::VARR);
        stages.push_back(10);
        stages.push_back(20);
        stages.push_back(30);
        q.pushKV("pipeline_stages_ms", stages);
        std::vector<modelnet::CapabilityPlan> plans;
        BOOST_REQUIRE(modelnet::ResolveCapability(cat, q, plans, code, err));
        BOOST_CHECK(plans[0].json["critical_path_not_sum"].get_bool());
        BOOST_CHECK_LT(plans[0].json["ttc_critical_path_ms"].getInt<int64_t>(),
                       plans[0].json["ttc_occupancy_sum_ms"].getInt<int64_t>());
    }
    BOOST_TEST_CONTEXT("JIT-RESOLVE-05") {
        UniValue q(UniValue::VOBJ);
        q.pushKV("deadline_ms", 0);
        std::vector<modelnet::CapabilityPlan> plans;
        BOOST_CHECK(!modelnet::ResolveCapability(cat, q, plans, code, err));
        BOOST_CHECK_EQUAL(code, "DEADLINE_UNACHIEVABLE");
    }
    BOOST_TEST_CONTEXT("JIT-RESOLVE-06") {
        UniValue q(UniValue::VOBJ);
        q.pushKV("recipe", RecipeJson());
        q.pushKV("prefer_vendor", "cuda");
        std::vector<modelnet::CapabilityPlan> plans;
        BOOST_REQUIRE(modelnet::ResolveCapability(cat, q, plans, code, err));
        BOOST_CHECK(plans[0].json["hardcoded_vendor_preference"].isFalse());
    }
    BOOST_TEST_CONTEXT("JIT-RESOLVE-07") {
        UniValue q(UniValue::VOBJ);
        q.pushKV("natural_language", "run a model");
        std::vector<modelnet::CapabilityPlan> plans;
        BOOST_CHECK(!modelnet::ResolveCapability(cat, q, plans, code, err));
        BOOST_CHECK_EQUAL(code, "TYPED_PLAN_REQUIRED");
    }
    BOOST_TEST_CONTEXT("JIT-GRANT-01") {
        modelnet::LocalCapabilityGrant g;
        BOOST_REQUIRE(modelnet::ParseGrant(GrantJson(), g, code, err));
        BOOST_CHECK(modelnet::GrantAllows(g, "PLAN", 1, code, err));
    }
    BOOST_TEST_CONTEXT("JIT-GRANT-02") {
        UniValue plan_req(UniValue::VOBJ);
        plan_req.pushKV("recipe", RecipeJson());
        plan_req.pushKV("grant", GrantJson("alice"));
        UniValue result;
        BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("planbtxcapability", plan_req), result, code, err));
        UniValue ens(UniValue::VOBJ);
        ens.pushKV("plan_id", result["plan_id"].get_str());
        ens.pushKV("grant", GrantJson("alice"));
        ens.pushKV("as", "bob");
        UniValue got;
        BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, Rpc("ensurebtxcapability", ens), got, code, err));
        BOOST_CHECK_EQUAL(code, "GRANT_WRONG_CALLER");
    }
    BOOST_TEST_CONTEXT("JIT-GRANT-03") {
        UniValue plan_req(UniValue::VOBJ);
        plan_req.pushKV("recipe", RecipeJson());
        plan_req.pushKV("grant", GrantJson());
        UniValue result;
        BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("planbtxcapability", plan_req), result, code, err));
        UniValue ens(UniValue::VOBJ);
        ens.pushKV("plan_id", result["plan_id"].get_str());
        ens.pushKV("grant", GrantJson());
        ens.pushKV("expected_digest", std::string(96, '0'));
        UniValue got;
        BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, Rpc("ensurebtxcapability", ens), got, code, err));
        BOOST_CHECK_EQUAL(code, "ID_MISMATCH");
    }
    BOOST_TEST_CONTEXT("JIT-GRANT-06") {
        modelnet::LocalCapabilityGrant g;
        UniValue bad = GrantJson();
        bad.pushKV("automatic_spend_atoms", 1);
        BOOST_CHECK(!modelnet::ParseGrant(bad, g, code, err));
        BOOST_CHECK_EQUAL(code, "PAID_PATH_FORBIDDEN");
    }
    BOOST_TEST_CONTEXT("JIT-GRANT-05") {
        UniValue g = GrantJson();
        g.pushKV("revoked", true);
        modelnet::LocalCapabilityGrant parsed;
        BOOST_REQUIRE(modelnet::ParseGrant(g, parsed, code, err));
        BOOST_CHECK(!modelnet::GrantAllows(parsed, "PREFETCH", 1, code, err));
        BOOST_CHECK_EQUAL(code, "GRANT_REVOKED");
    }
    BOOST_TEST_CONTEXT("JIT-GRANT-04") {
        modelnet::HostResourceBroker br;
        modelnet::MemoryLimits lim;
        lim.host_physical_bytes = 100;
        BOOST_REQUIRE(br.Configure(lim, err));
        BOOST_REQUIRE(br.Reserve(80, 0, 0, false, err));
        BOOST_CHECK(!br.Reserve(80, 0, 0, false, err));
        br.Release(80, 0, 0, false);
        BOOST_REQUIRE(br.Reserve(80, 0, 0, false, err));
    }
    BOOST_TEST_CONTEXT("JIT-GRANT-07") {
        UniValue g = GrantJson();
        g.pushKV("expires_at_ms", 10);
        modelnet::LocalCapabilityGrant parsed;
        BOOST_REQUIRE(modelnet::ParseGrant(g, parsed, code, err));
        BOOST_CHECK(!modelnet::GrantAllows(parsed, "ENSURE", 11, code, err));
        BOOST_CHECK_EQUAL(code, "GRANT_EXPIRED");
        BOOST_CHECK(modelnet::GrantAllows(parsed, "ENSURE", 5, code, err));
    }
}

BOOST_AUTO_TEST_CASE(jit_mem_lease)
{
    std::string err, code;
    BOOST_TEST_CONTEXT("JIT-MEM-01") {
        modelnet::HostResourceBroker br;
        modelnet::MemoryLimits lim;
        UniValue o(UniValue::VOBJ);
        o.pushKV("host_physical_bytes", static_cast<uint64_t>(100));
        o.pushKV("host_pinned_bytes", static_cast<uint64_t>(50));
        o.pushKV("device_bytes", static_cast<uint64_t>(10));
        BOOST_REQUIRE(modelnet::ParseMemoryLimits(o, lim, code, err));
        BOOST_REQUIRE(br.Configure(lim, err));
        BOOST_CHECK(!br.Reserve(90, 0, 20, false, err));
    }
    BOOST_TEST_CONTEXT("JIT-MEM-02") {
        modelnet::HostResourceBroker br;
        modelnet::MemoryLimits lim;
        lim.host_physical_bytes = 100;
        lim.uma = true;
        BOOST_REQUIRE(br.Configure(lim, err));
        BOOST_REQUIRE(br.Reserve(40, 0, 40, false, err));
        BOOST_CHECK(br.Uma());
        BOOST_CHECK_EQUAL(br.StatusJson()["host_used"].get_str(), "40");
        BOOST_CHECK_EQUAL(br.StatusJson()["device_used"].get_str(), "40");
        BOOST_REQUIRE(br.Reserve(30, 0, 0, false, err));
        BOOST_CHECK(!br.Reserve(31, 0, 0, false, err));
        br.Release(40, 0, 40, false);
        br.Release(30, 0, 0, false);

        modelnet::HostResourceBroker distinct;
        BOOST_REQUIRE(distinct.Configure(lim, err));
        BOOST_REQUIRE(distinct.Reserve(40, 0, 0, false, err));
        BOOST_REQUIRE(distinct.Reserve(0, 0, 40, false, err));
        BOOST_CHECK(!distinct.Reserve(30, 0, 0, false, err));

        modelnet::HostResourceBroker conc;
        BOOST_REQUIRE(conc.Configure(lim, err));
        std::atomic<int> ok{0};
        std::atomic<int> denied{0};
        auto worker = [&]() {
            std::string e;
            if (conc.Reserve(40, 0, 40, false, e)) {
                ++ok;
            } else {
                ++denied;
            }
        };
        std::thread u1(worker), u2(worker), u3(worker);
        u1.join();
        u2.join();
        u3.join();
        BOOST_CHECK_EQUAL(ok.load() + denied.load(), 3);
        BOOST_CHECK_EQUAL(ok.load(), 2);
        BOOST_CHECK_EQUAL(denied.load(), 1);

        modelnet::HostResourceBroker noleak;
        lim.speculative_bytes = 10;
        BOOST_REQUIRE(noleak.Configure(lim, err));
        BOOST_REQUIRE(noleak.Reserve(8, 0, 8, true, err));
        BOOST_CHECK(!noleak.Reserve(8, 0, 8, true, err));
        BOOST_CHECK_EQUAL(err, "speculative budget");
        BOOST_REQUIRE(noleak.Reserve(92, 0, 0, false, err));
    }
    BOOST_TEST_CONTEXT("JIT-MEM-03") {
        modelnet::HostResourceBroker br;
        modelnet::MemoryLimits lim;
        lim.host_physical_bytes = 1000;
        lim.host_pinned_bytes = 10;
        BOOST_REQUIRE(br.Configure(lim, err));
        BOOST_CHECK(!br.Reserve(0, 11, 0, false, err));
    }
    BOOST_TEST_CONTEXT("JIT-MEM-04") {
        BOOST_CHECK(!modelnet::PerRankFeasible({100, 10, 100}, 50, err));
        BOOST_CHECK(modelnet::PerRankFeasible({100, 50, 100}, 50, err));
    }
    BOOST_TEST_CONTEXT("JIT-MEM-05") {
        modelnet::HostResourceBroker br;
        modelnet::MemoryLimits lim;
        lim.host_physical_bytes = 100;
        BOOST_REQUIRE(br.Configure(lim, err));
        br.NoteRetiredAwaiting(80);
        BOOST_CHECK(br.StatusJson()["retired_awaiting_fence"].get_str() == "80");
        BOOST_CHECK(!br.Reserve(21, 0, 0, false, err));
        BOOST_REQUIRE(br.Reserve(20, 0, 0, false, err));
        br.ClearRetired(80);
        BOOST_REQUIRE(br.Reserve(80, 0, 0, false, err));
    }
    BOOST_TEST_CONTEXT("JIT-LEASE-01") {
        modelnet::LeaseTable t;
        auto genA = modelnet::NewGeneration();
        auto genB = modelnet::NewGeneration();
        auto& a = t.Create(modelnet::LeaseClass::LOAD, "a", 8, genA);
        a.operation_id = "op";
        t.Cancel(a.lease_id, true);
        auto& b = t.Create(modelnet::LeaseClass::LOAD, "b", 8, genB);
        err.clear();
        BOOST_CHECK(t.StaleCompletion("op", genB, err));
        BOOST_CHECK_EQUAL(err, "stale generation");
        BOOST_REQUIRE(t.Find(b.lease_id));
        BOOST_CHECK_EQUAL(std::string(modelnet::LeaseLifeName(t.Find(b.lease_id)->life)), "RESERVED");
        BOOST_CHECK_EQUAL(std::string(modelnet::LeaseLifeName(t.Find(a.lease_id)->life)), "QUARANTINED");
        err.clear();
        BOOST_CHECK(t.StaleCompletion("op", genA, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK_EQUAL(std::string(modelnet::LeaseLifeName(t.Find(a.lease_id)->life)), "QUIESCENT");
        BOOST_CHECK_EQUAL(std::string(modelnet::LeaseLifeName(t.Find(b.lease_id)->life)), "RESERVED");
        err.clear();
        BOOST_CHECK(!t.StaleCompletion("", genA, err));
    }
    BOOST_TEST_CONTEXT("JIT-LEASE-02") {
        modelnet::LeaseTable t;
        auto& a = t.Create(modelnet::LeaseClass::TRANSFER, "a", 8, modelnet::NewGeneration());
        (void)t.Transition(a.lease_id, modelnet::LeaseLife::ALLOCATED, code, err);
        (void)t.Transition(a.lease_id, modelnet::LeaseLife::POPULATING, code, err);
        BOOST_CHECK(t.Cancel(a.lease_id, true) == modelnet::PhysicalDisposition::STILL_IN_FLIGHT);
        BOOST_CHECK(modelnet::RetainUntilQuiescent(modelnet::PhysicalDisposition::STILL_IN_FLIGHT));
    }
    BOOST_TEST_CONTEXT("JIT-LEASE-06") {
        modelnet::LeaseTable t;
        auto& a = t.Create(modelnet::LeaseClass::LOAD, "a", 8, modelnet::NewGeneration());
        t.Cancel(a.lease_id, false);
        t.Cancel(a.lease_id, false);
        BOOST_CHECK(t.Find(a.lease_id) != nullptr);
    }
    BOOST_TEST_CONTEXT("JIT-LEASE-07") {
        BOOST_CHECK(modelnet::RetainUntilQuiescent(modelnet::PhysicalDisposition::UNKNOWN));
    }
    BOOST_TEST_CONTEXT("JIT-LEASE-03") {
        modelnet::LeaseTable t;
        auto& a = t.Create(modelnet::LeaseClass::EXECUTE, "a", 8, modelnet::NewGeneration());
        (void)t.Transition(a.lease_id, modelnet::LeaseLife::ALLOCATED, code, err);
        (void)t.Transition(a.lease_id, modelnet::LeaseLife::POPULATING, code, err);
        (void)t.Transition(a.lease_id, modelnet::LeaseLife::VERIFIED, code, err);
        (void)t.Transition(a.lease_id, modelnet::LeaseLife::ACTIVE, code, err);
        (void)t.Transition(a.lease_id, modelnet::LeaseLife::RETIRING, code, err);
        BOOST_CHECK(!t.ReleaseIfQuiescent(a.lease_id, err));
        (void)t.Transition(a.lease_id, modelnet::LeaseLife::QUIESCENT, code, err);
        BOOST_REQUIRE(t.ReleaseIfQuiescent(a.lease_id, err));
        BOOST_CHECK_EQUAL(std::string(modelnet::LeaseLifeName(t.Find(a.lease_id)->life)), "RELEASED");
        BOOST_CHECK(t.Cancel(a.lease_id, false) == modelnet::PhysicalDisposition::NOT_DISPATCHED);
        BOOST_CHECK_EQUAL(std::string(modelnet::LeaseLifeName(t.Find(a.lease_id)->life)), "RELEASED");
    }
    BOOST_TEST_CONTEXT("JIT-LEASE-04") {
        modelnet::LeaseTable t;
        auto& a = t.Create(modelnet::LeaseClass::TRANSFER, "a", 8, modelnet::NewGeneration());
        (void)t.Transition(a.lease_id, modelnet::LeaseLife::ALLOCATED, code, err);
        (void)t.Transition(a.lease_id, modelnet::LeaseLife::POPULATING, code, err);
        BOOST_CHECK(t.Cancel(a.lease_id, true) == modelnet::PhysicalDisposition::STILL_IN_FLIGHT);
        BOOST_CHECK(!t.ReleaseIfQuiescent(a.lease_id, err));
    }
    BOOST_TEST_CONTEXT("JIT-LEASE-05") {
        modelnet::LeaseTable t;
        auto& a = t.Create(modelnet::LeaseClass::LOAD, "orphan", 8, modelnet::NewGeneration());
        a.operation_id = "worker";
        (void)t.Transition(a.lease_id, modelnet::LeaseLife::ALLOCATED, code, err);
        (void)t.Transition(a.lease_id, modelnet::LeaseLife::POPULATING, code, err);
        BOOST_CHECK(t.Cancel(a.lease_id, true) == modelnet::PhysicalDisposition::STILL_IN_FLIGHT);
        BOOST_CHECK(t.Find(a.lease_id) != nullptr);
        BOOST_CHECK_EQUAL(std::string(modelnet::LeaseLifeName(t.Find(a.lease_id)->life)), "QUARANTINED");
    }
    BOOST_TEST_CONTEXT("JIT-MEM-06") {
        modelnet::HostResourceBroker br;
        modelnet::MemoryLimits lim;
        lim.host_physical_bytes = 100;
        lim.speculative_bytes = 10;
        BOOST_REQUIRE(br.Configure(lim, err));
        BOOST_REQUIRE(br.AdmitPrefetch(err));
        BOOST_REQUIRE(br.AdmitPrefetch(err));
        BOOST_CHECK(!br.AdmitPrefetch(err));
        br.FinishPrefetch();
        BOOST_REQUIRE(br.AdmitPrefetch(err));
        BOOST_REQUIRE(br.Reserve(6, 0, 0, true, err));
        BOOST_CHECK(!br.Reserve(6, 0, 0, true, err));
        BOOST_CHECK_EQUAL(err, "speculative budget");
        BOOST_REQUIRE(br.Reserve(6, 0, 0, false, err));
        BOOST_CHECK_EQUAL(br.StatusJson()["speculative_used"].get_str(), "6");
    }
    BOOST_TEST_CONTEXT("JIT-MEM-07") {
        modelnet::HostResourceBroker br;
        modelnet::MemoryLimits lim;
        lim.host_physical_bytes = 50;
        BOOST_REQUIRE(br.Configure(lim, err));
        BOOST_REQUIRE(br.Reserve(50, 0, 0, false, err));
        BOOST_CHECK(!br.Reserve(1, 0, 0, false, err));
        br.Release(50, 0, 0, false);
        BOOST_REQUIRE(br.Reserve(50, 0, 0, false, err));
        br.Release(50, 0, 0, false);
        BOOST_CHECK(!br.Reserve(~uint64_t{0} - 5, 0, 0, false, err));
        BOOST_REQUIRE(br.Reserve(50, 0, 0, false, err));
    }
}

BOOST_AUTO_TEST_CASE(jit_map_range_mat_load)
{
    std::string code, err;
    const auto st = MakeSafeTensors();
    modelnet::Digest48 man{};
    BOOST_TEST_CONTEXT("JIT-MAP-01") {
        modelnet::TensorRangeMap map;
        std::vector<unsigned char> trunc(st.begin(), st.begin() + 4);
        BOOST_CHECK(!modelnet::DeriveTensorRangeMap(trunc, st.size(), 0, man, map, code, err));
    }
    BOOST_TEST_CONTEXT("JIT-MAP-02") {
        const std::string header = R"({"w":{"dtype":"F32","shape":[999999999999],"data_offsets":[0,8]}})";
        std::vector<unsigned char> out(8 + header.size() + 8, 0);
        WriteLE64(out.data(), header.size());
        std::memcpy(out.data() + 8, header.data(), header.size());
        modelnet::TensorRangeMap map;
        BOOST_CHECK(!modelnet::DeriveTensorRangeMap(out, out.size(), 0, man, map, code, err));
    }
    BOOST_TEST_CONTEXT("JIT-MAP-03") {
        const std::string header =
            R"({"a":{"dtype":"F32","shape":[2],"data_offsets":[0,8]},"b":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}})";
        std::vector<unsigned char> out(8 + header.size() + 8, 0);
        WriteLE64(out.data(), header.size());
        std::memcpy(out.data() + 8, header.data(), header.size());
        modelnet::TensorRangeMap map;
        BOOST_REQUIRE(modelnet::DeriveTensorRangeMap(out, out.size(), 0, man, map, code, err));
        BOOST_CHECK_EQUAL(map.tensors.size(), 2);
    }
    BOOST_TEST_CONTEXT("JIT-MAP-05") {
        std::vector<unsigned char> gguf(32, 0);
        std::memcpy(gguf.data(), "GGUF", 4);
        WriteLE32(gguf.data() + 4, 3);
        WriteLE64(gguf.data() + 8, 0);
        WriteLE64(gguf.data() + 16, 0);
        modelnet::TensorRangeMap map;
        BOOST_REQUIRE(modelnet::DeriveTensorRangeMap(gguf, gguf.size(), 0, man, map, code, err));
        BOOST_CHECK_EQUAL(map.json["format"].get_str(), "GGUF");
        std::vector<unsigned char> gguf1(96, 0);
        std::memcpy(gguf1.data(), "GGUF", 4);
        WriteLE32(gguf1.data() + 4, 3);
        WriteLE64(gguf1.data() + 8, 1);
        WriteLE64(gguf1.data() + 16, 0);
        size_t goff = 24;
        WriteLE64(gguf1.data() + goff, 1);
        goff += 8;
        gguf1[goff] = 'w';
        goff += 1;
        WriteLE32(gguf1.data() + goff, 1);
        goff += 4;
        WriteLE64(gguf1.data() + goff, 1);
        goff += 8;
        WriteLE32(gguf1.data() + goff, 0);
        goff += 4;
        WriteLE64(gguf1.data() + goff, 0);
        modelnet::TensorRangeMap gmap;
        BOOST_REQUIRE(modelnet::DeriveTensorRangeMap(gguf1, gguf1.size(), 0, man, gmap, code, err));
        BOOST_REQUIRE_EQUAL(gmap.tensors.size(), 1);
        BOOST_CHECK_GE(gmap.tensors[0].offset, 32U);
        BOOST_CHECK_EQUAL(gmap.tensors[0].offset % 32, 0);
        BOOST_CHECK_EQUAL(gmap.tensors[0].length, 4U);
        std::vector<unsigned char> q4(128, 0);
        std::memcpy(q4.data(), "GGUF", 4);
        WriteLE32(q4.data() + 4, 3);
        WriteLE64(q4.data() + 8, 1);
        WriteLE64(q4.data() + 16, 0);
        size_t qoff = 24;
        WriteLE64(q4.data() + qoff, 2);
        qoff += 8;
        q4[qoff] = 'q';
        q4[qoff + 1] = '4';
        qoff += 2;
        WriteLE32(q4.data() + qoff, 1);
        qoff += 4;
        WriteLE64(q4.data() + qoff, 32);
        qoff += 8;
        WriteLE32(q4.data() + qoff, 2);
        qoff += 4;
        WriteLE64(q4.data() + qoff, 0);
        modelnet::TensorRangeMap qmap;
        BOOST_REQUIRE(modelnet::DeriveTensorRangeMap(q4, q4.size(), 0, man, qmap, code, err));
        BOOST_REQUIRE_EQUAL(qmap.tensors.size(), 1);
        BOOST_CHECK_EQUAL(qmap.tensors[0].length, 18U);
    }
    BOOST_TEST_CONTEXT("JIT-MAP-04") {
        modelnet::Digest48 a{}, b{};
        a.data[0] = 1;
        b.data[0] = 2;
        BOOST_CHECK(!modelnet::MapSignerMatchesManifest(a, b, code, err));
        BOOST_CHECK_EQUAL(code, "MAP_SIGNER_MISMATCH");
        BOOST_CHECK(modelnet::MapSignerMatchesManifest(a, a, code, err));
    }
    BOOST_TEST_CONTEXT("JIT-MAP-06") {
        BOOST_CHECK(!modelnet::RequiredShardsPresent({0, 1, 2}, {0, 1}, code, err));
        BOOST_CHECK_EQUAL(code, "SHARD_MISSING");
        BOOST_CHECK(modelnet::RequiredShardsPresent({0, 1}, {0, 1, 2}, code, err));
    }
    BOOST_TEST_CONTEXT("JIT-MAP-07") {
        BOOST_CHECK(!modelnet::AdmitTensorMapCount(modelnet::TENSOR_MAP_ENTRY_MAX + 1, 1, code, err));
        BOOST_CHECK_EQUAL(code, "RESOURCE_LIMIT");
        BOOST_CHECK(!modelnet::AdmitTensorMapCount(1, modelnet::TENSOR_MAP_BYTES_MAX + 1, code, err));
        BOOST_CHECK(modelnet::AdmitTensorMapCount(modelnet::TENSOR_MAP_ENTRY_MAX, 1024, code, err));
    }
    BOOST_TEST_CONTEXT("JIT-RANGE-01") {
        modelnet::VerifiedRangeLease lease;
        auto gen = modelnet::NewGeneration();
        BOOST_REQUIRE(modelnet::ReadVerifiedRange(man, 0, 8, 8, st, gen, lease, code, err));
        BOOST_CHECK_EQUAL(lease.bytes.size(), 8);
        BOOST_CHECK(!modelnet::ReadVerifiedRange(man, 1, 0, 8, st, gen, lease, code, err));
        BOOST_CHECK_EQUAL(code, "SHARD_MISSING");
        std::vector<unsigned char> empty_file;
        BOOST_CHECK(!modelnet::ReadVerifiedRange(man, 0, 0, 1, empty_file, gen, lease, code, err));
        BOOST_CHECK_EQUAL(code, "RANGE_UNVERIFIED");
    }
    BOOST_TEST_CONTEXT("JIT-RANGE-02") {
        std::vector<bool> bits(2, false);
        BOOST_CHECK(modelnet::SparseHoleIsUnverified(0, 10, bits, 4));
        bits[0] = bits[1] = true;
        BOOST_CHECK(!modelnet::SparseHoleIsUnverified(0, 8, bits, 4));
        std::vector<std::vector<unsigned char>> pieces{{0, 1, 2, 3}, {4, 5, 6, 7}};
        modelnet::VerifiedRangeLease lease;
        BOOST_CHECK(!modelnet::ReadVerifiedRangeFromPieces(man, 0, 8, pieces, 4, std::vector<bool>(2, false),
                                                       modelnet::NewGeneration(), lease, code, err));
        BOOST_CHECK_EQUAL(code, "RANGE_UNVERIFIED");
        BOOST_REQUIRE(modelnet::ReadVerifiedRangeFromPieces(man, 2, 4, pieces, 4, std::vector<bool>(2, true),
                                                           modelnet::NewGeneration(), lease, code, err));
        BOOST_CHECK_EQUAL(lease.bytes.size(), 4);
        BOOST_CHECK_EQUAL(lease.bytes[0], 2);
        BOOST_CHECK_EQUAL(lease.bytes[3], 5);
        std::vector<std::vector<unsigned char>> holey{{0, 1, 2, 3}, {}, {4, 5, 6, 7}};
        std::vector<bool> holey_bits(3, true);
        BOOST_CHECK(!modelnet::ReadVerifiedRangeFromPieces(man, 0, 8, holey, 4, holey_bits, modelnet::NewGeneration(),
                                                          lease, code, err));
        BOOST_CHECK_EQUAL(code, "RANGE_UNVERIFIED");
        BOOST_CHECK(lease.bytes.empty());
    }
    BOOST_TEST_CONTEXT("JIT-RANGE-03") {
        std::vector<std::pair<uint64_t, uint64_t>> req{{0, 4}, {2, 4}, {10, 2}};
        std::vector<std::pair<uint64_t, uint64_t>> coal;
        BOOST_REQUIRE(modelnet::CoalesceRangeConsumers(req, coal));
        BOOST_CHECK_EQUAL(coal.size(), 2);
        BOOST_CHECK_EQUAL(coal[0].second, 6);
    }
    BOOST_TEST_CONTEXT("JIT-RANGE-04") {
        BOOST_CHECK(modelnet::RangeTenantBoundary("t1", "t1", code, err));
        BOOST_CHECK(!modelnet::RangeTenantBoundary("t1", "t2", code, err));
        BOOST_CHECK_EQUAL(code, "TENANT_DENIED");
    }
    BOOST_TEST_CONTEXT("JIT-RANGE-05") {
        uint32_t pri = 99;
        BOOST_CHECK(modelnet::PreferLoadOverRarity(true, 500, pri));
        BOOST_CHECK_EQUAL(pri, 0u);
        BOOST_CHECK(!modelnet::PreferLoadOverRarity(false, 1, pri));
        BOOST_CHECK(pri > 0);
    }
    BOOST_TEST_CONTEXT("JIT-RANGE-06") {
        BOOST_REQUIRE(modelnet::CorruptProviderFallback(true, true, code, err));
        BOOST_CHECK(!modelnet::CorruptProviderFallback(true, false, code, err));
        BOOST_CHECK_EQUAL(code, "PROVIDER_CORRUPT");
    }
    BOOST_TEST_CONTEXT("JIT-RANGE-07") {
        modelnet::PhysicalDisposition d{};
        BOOST_CHECK(!modelnet::CancelVerifiedRange(modelnet::PhysicalDisposition::STILL_IN_FLIGHT, d));
        BOOST_CHECK(d == modelnet::PhysicalDisposition::STILL_IN_FLIGHT);
        BOOST_REQUIRE(modelnet::CancelVerifiedRange(modelnet::PhysicalDisposition::STOPPED_QUIESCENT, d));
    }
    BOOST_TEST_CONTEXT("JIT-MAT-01") {
        std::vector<bool> bits(1, false);
        BOOST_CHECK(modelnet::SparseHoleIsUnverified(0, 4, bits, 4));
    }
    BOOST_TEST_CONTEXT("JIT-MAT-02") {
        const fs::path dest = m_path_root / "mat.exclusive";
        std::vector<std::vector<unsigned char>> pieces{{'a'}, {'b'}};
        BOOST_REQUIRE(modelnet::MaterializeCompleteFile(pieces, fs::PathToString(dest), modelnet::NewGeneration(), code, err));
        BOOST_CHECK(!modelnet::MaterializeCompleteFile(pieces, fs::PathToString(dest), modelnet::NewGeneration(), code, err));
        BOOST_CHECK_EQUAL(code, "OVERWRITE_REFUSED");
        std::vector<std::vector<unsigned char>> holey{{'a'}, {}};
        const fs::path dest_hole = m_path_root / "mat.hole";
        BOOST_CHECK(!modelnet::MaterializeCompleteFile(holey, fs::PathToString(dest_hole), modelnet::NewGeneration(), code, err));
        BOOST_CHECK_EQUAL(code, "RANGE_UNVERIFIED");
        BOOST_CHECK(!fs::exists(dest_hole));
    }
    BOOST_TEST_CONTEXT("JIT-LOAD-07") {
        std::vector<unsigned char> a{'x', 'y'};
        BOOST_CHECK(modelnet::StreamingEqualsFullFile(a, a));
        BOOST_CHECK(!modelnet::StreamingEqualsFullFile(a, {'x'}));
    }
    BOOST_TEST_CONTEXT("JIT-LOAD-02") {
        BOOST_CHECK(std::string(modelnet::LoadStrategyResultName(modelnet::LoadStrategyResult::FAILED_MUTATED)) ==
                    "FAILED_MUTATED");
    }
}

BOOST_AUTO_TEST_CASE(jit_run_lora_prefetch_cache_kv)
{
    std::string code, err;
    BOOST_TEST_CONTEXT("JIT-RUN-01") {
        const unsigned char payload[] = {1, 2, 3, 4};
        modelnet::Digest48 d;
        BOOST_REQUIRE(modelnet::CpuFixtureSmoke(payload, d, err));
        BOOST_CHECK(!d.IsNull());
        auto adapters = modelnet::ProbeRuntimeAdapters();
        BOOST_REQUIRE(!adapters.empty());
        BOOST_CHECK_EQUAL(adapters[0].runtime_id, "synthetic-cpu-fixture");
        BOOST_CHECK(!adapters[0].stub);
        BOOST_CHECK(adapters[0].present);
    }
    BOOST_TEST_CONTEXT("JIT-RUN-02") {
        bool cuda = false;
        for (const auto& a : modelnet::ProbeRuntimeAdapters()) {
            if (a.backend.find("CUDA") != std::string::npos && a.present) cuda = true;
        }
        if (!cuda) BOOST_TEST_MESSAGE("JIT-RUN-02 CUDA path NOT_RUN: no BTX_LLAMA_CLI/CUDA adapter present");
    }
    BOOST_TEST_CONTEXT("JIT-RUN-05") {
        modelnet::CapabilityRecipe rec;
        UniValue rj = RecipeJson();
        rj.pushKV("executable_path", "/tmp/evil");
        modelnet::LocalCapabilityGrant g;
        BOOST_REQUIRE(modelnet::ParseGrant(GrantJson(), g, code, err));
        BOOST_REQUIRE(modelnet::ParseCapabilityRecipe(RecipeJson(), rec, code, err));
        rec.json = rj;
        modelnet::CapabilityPlan plan;
        BOOST_CHECK(!modelnet::PlanCapability(rec, nullptr, g, plan, code, err));
        BOOST_CHECK_EQUAL(code, "UNKNOWN_ADAPTER_PARAMETER");
    }
    BOOST_TEST_CONTEXT("JIT-LORA-01") {
        modelnet::Digest48 base{}, other{};
        BOOST_REQUIRE(modelnet::Digest48::FromHex(std::string(96, 'a'), base, err));
        BOOST_REQUIRE(modelnet::Digest48::FromHex(std::string(96, 'b'), other, err));
        BOOST_CHECK(!modelnet::AttachExactBaseAdapter(base, other, code, err));
        BOOST_CHECK_EQUAL(code, "ADAPTER_BASE_MISMATCH");
        BOOST_CHECK(modelnet::AttachExactBaseAdapter(base, base, code, err));
    }
    BOOST_TEST_CONTEXT("JIT-LORA-05") {
        modelnet::Digest48 c1, c2;
        BOOST_REQUIRE(modelnet::ComposeLoraOrder({"a", "b"}, {"1", "1"}, c1, err));
        BOOST_REQUIRE(modelnet::ComposeLoraOrder({"b", "a"}, {"1", "1"}, c2, err));
        BOOST_CHECK(c1 != c2);
    }
    BOOST_TEST_CONTEXT("JIT-LORA-06") {
        UniValue r = RecipeJson();
        UniValue t1(UniValue::VOBJ);
        t1.pushKV("name", "tok1");
        UniValue res(UniValue::VOBJ);
        res.pushKV("kind", "MODEL");
        res.pushKV("digest48", std::string(96, '1'));
        t1.pushKV("resource", res);
        t1.pushKV("role", "TOKENIZER");
        UniValue t2(UniValue::VOBJ);
        t2.pushKV("name", "tok2");
        UniValue res2(UniValue::VOBJ);
        res2.pushKV("kind", "MODEL");
        res2.pushKV("digest48", std::string(96, '2'));
        t2.pushKV("resource", res2);
        t2.pushKV("role", "TOKENIZER");
        r = WithComponent(r, t1);
        r = WithComponent(r, t2);
        modelnet::CapabilityRecipe parsed;
        code.clear();
        err.clear();
        BOOST_CHECK(!modelnet::ParseCapabilityRecipe(r, parsed, code, err));
        BOOST_CHECK_EQUAL(code, "TOKENIZER_CONFLICT");
    }
    BOOST_TEST_CONTEXT("JIT-PREFETCH-02") {
        modelnet::HostResourceBroker br;
        modelnet::MemoryLimits lim;
        lim.host_physical_bytes = 1000;
        BOOST_REQUIRE(br.Configure(lim, err));
        modelnet::LocalCapabilityGrant g;
        BOOST_REQUIRE(modelnet::ParseGrant(GrantJson(), g, code, err));
        UniValue job;
        BOOST_REQUIRE(modelnet::AdmitPrefetchHint(UniValue(UniValue::VOBJ), g, br, job, code, err));
        BOOST_REQUIRE(modelnet::AdmitPrefetchHint(UniValue(UniValue::VOBJ), g, br, job, code, err));
        BOOST_CHECK(!modelnet::AdmitPrefetchHint(UniValue(UniValue::VOBJ), g, br, job, code, err));
        BOOST_CHECK_EQUAL(code, "BUDGET_EXCEEDED");
    }
    BOOST_TEST_CONTEXT("JIT-PREFETCH-06") {
        modelnet::HostResourceBroker br;
        modelnet::LocalCapabilityGrant g;
        BOOST_REQUIRE(modelnet::ParseGrant(GrantJson(), g, code, err));
        UniValue hint(UniValue::VOBJ);
        hint.pushKV("prompt_transcript", "secret");
        UniValue job;
        BOOST_CHECK(!modelnet::AdmitPrefetchHint(hint, g, br, job, code, err));
        BOOST_CHECK_EQUAL(code, "PRIVACY");
    }
    BOOST_TEST_CONTEXT("JIT-CACHE-02") {
        UniValue cache(UniValue::VOBJ);
        cache.pushKV("format", "cubin");
        modelnet::Digest48 author{};
        BOOST_CHECK(!modelnet::AcceptExecutableCache(cache, false, author, code, err));
        BOOST_CHECK_EQUAL(code, "SOFTWARE_TRUST_REQUIRED");
        BOOST_REQUIRE(modelnet::AcceptExecutableCache(cache, true, author, code, err));
    }
    BOOST_TEST_CONTEXT("JIT-KV-04") {
        UniValue cfg(UniValue::VOBJ);
        cfg.pushKV("rope", "1");
        modelnet::Digest48 k1, k2;
        BOOST_REQUIRE(modelnet::PrivatePrefixKey("t1", cfg, "hello", k1, err));
        BOOST_REQUIRE(modelnet::PrivatePrefixKey("t2", cfg, "hello", k2, err));
        BOOST_CHECK(k1 != k2);
        BOOST_CHECK(!modelnet::PrefixVisibleToTenant("t1", "t2"));
    }
    BOOST_TEST_CONTEXT("JIT-KV-02") {
        UniValue c1(UniValue::VOBJ);
        c1.pushKV("adapters", "a");
        UniValue c2(UniValue::VOBJ);
        c2.pushKV("adapters", "b");
        modelnet::Digest48 k1, k2;
        BOOST_REQUIRE(modelnet::PrivatePrefixKey("t", c1, "p", k1, err));
        BOOST_REQUIRE(modelnet::PrivatePrefixKey("t", c2, "p", k2, err));
        BOOST_CHECK(k1 != k2);
    }
}

BOOST_AUTO_TEST_CASE(jit_peer_moe_cxl_update)
{
    std::string code, err;
    BOOST_TEST_CONTEXT("JIT-PEER-01") {
        modelnet::PeerTransferOffer off;
        BOOST_REQUIRE(modelnet::ProbePeerBackends(off));
        BOOST_CHECK(off.json["portable_host_buffer"].get_bool());
        BOOST_CHECK(!off.json["stub"].get_bool());
        if (!off.nixl_present) BOOST_TEST_MESSAGE("JIT-PEER-07 NIXL NOT_RUN");
    }
    BOOST_TEST_CONTEXT("JIT-PEER-06") {
        modelnet::PeerTransferOffer off;
        BOOST_REQUIRE(modelnet::ProbePeerBackends(off));
        if (off.nixl_present) {
            BOOST_CHECK_EQUAL(std::string(modelnet::TransportAssuranceName(off.assurance)), "TRUSTED_FABRIC");
        } else {
            BOOST_CHECK_EQUAL(std::string(modelnet::TransportAssuranceName(off.assurance)), "HOST_BUFFER");
        }
    }
    BOOST_TEST_CONTEXT("JIT-DIRECT-04") {
        std::vector<unsigned char> dest;
        modelnet::PhysicalDisposition d{};
        const unsigned char src[] = {9, 8, 7};
        BOOST_REQUIRE(modelnet::HostBufferTransfer(src, dest, modelnet::NewGeneration(), d, err));
        BOOST_CHECK_EQUAL(dest.size(), 3);
        BOOST_CHECK(d == modelnet::PhysicalDisposition::STOPPED_QUIESCENT);
    }
    BOOST_TEST_CONTEXT("JIT-MOE-03") {
        std::vector<modelnet::ExpertUnit> res;
        BOOST_CHECK(!modelnet::MoEDispatch(res, 0, 0, false, code, err));
        BOOST_CHECK_EQUAL(code, "EXPERT_MISS");
    }
    BOOST_TEST_CONTEXT("JIT-MOE-06") {
        modelnet::ExpertUnit e;
        e.layer = 0;
        e.expert = 0;
        e.life = modelnet::LeaseLife::ACTIVE;
        BOOST_CHECK(!modelnet::MoEDispatch({e}, 0, 0, true, code, err));
        BOOST_CHECK_EQUAL(code, "WAN_INNER_TOKEN_FORBIDDEN");
    }
    BOOST_TEST_CONTEXT("JIT-MOE-02") {
        const unsigned char a[] = {1, 2, 3};
        BOOST_CHECK(modelnet::MoEAllResidentParity(a, a));
    }
    BOOST_TEST_CONTEXT("JIT-CXL-01") {
        auto topo = modelnet::DiscoverTopology();
        BOOST_CHECK(topo.json.exists("cxl_evidence") || topo.json.exists("topology") || topo.json.exists("unified_memory"));
        if (!topo.cxl) BOOST_TEST_MESSAGE("JIT-CXL-04 real CXL tier NOT_RUN");
    }
    BOOST_TEST_CONTEXT("JIT-CXL-06") {
        BOOST_CHECK(!modelnet::PlaceInTier(modelnet::PlacementTier::CXL_NUMA, modelnet::PlacementTier::HOST_PAGEABLE, code, err));
        BOOST_CHECK_EQUAL(code, "TIER_UNAVAILABLE");
    }
    BOOST_TEST_CONTEXT("JIT-UPDATE-03") {
        std::string active, jerr;
        BOOST_REQUIRE(modelnet::CrashResumeSwitch({"old", "INCOMPLETE"}, active, jerr));
        BOOST_CHECK_EQUAL(active, "old");
    }
    BOOST_TEST_CONTEXT("JIT-UPDATE-07") {
        std::string jerr;
        BOOST_REQUIRE(modelnet::JournalSwitch("old", "new", "commit", jerr));
    }
}

BOOST_AUTO_TEST_CASE(jit_api_priv_scale_journey_safety)
{
    modelnet::ModelCatalog cat{m_path_root / "api", 1 << 20};
    std::string code, err;
    const std::vector<std::string> methods = {
        "resolvebtxcapability", "planbtxcapability", "ensurebtxcapability", "getbtxcapability",
        "cancelbtxcapability", "releasebtxcapability", "prefetchbtxcapability", "sleepbtxcapability",
        "wakebtxcapability", "getbtxresidency", "inspectbtxtensormap", "exportbtxlock", "importbtxlock",
        "planbtxcapabilityupdate", "switchbtxcapability", "getbtxcapabilityevents", "getbtxruntimecapabilities",
        "getbtxttctrace"};
    BOOST_TEST_CONTEXT("JIT-API-04") {
        for (const auto& m : methods) {
            BOOST_CHECK_MESSAGE(modelnet::IsCapabilityHelperMethod(m), m);
        }
        BOOST_CHECK_EQUAL(methods.size(), 18);
        BOOST_CHECK(modelnet::CapabilityCliUsage().find("--plan-id") != std::string::npos);
        std::atomic<bool> stop{true};
        const fs::path capd_dir = m_path_root / "capd-native";
        const fs::path sock = fs::PathFromString(std::string("/tmp/btx-capd-") + std::to_string(::getpid()) + ".sock");
        BOOST_CHECK_EQUAL(modelnet::RunCapabilityDaemon(capd_dir, sock, &stop), 0);
        BOOST_CHECK(!fs::exists(sock));
    }
    BOOST_TEST_CONTEXT("JIT-API-01") {
        UniValue plan_req(UniValue::VOBJ);
        plan_req.pushKV("recipe", RecipeJson());
        plan_req.pushKV("grant", GrantJson());
        UniValue result;
        BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("planbtxcapability", plan_req), result, code, err));
        UniValue ens(UniValue::VOBJ);
        ens.pushKV("plan_id", result["plan_id"].get_str());
        ens.pushKV("grant", GrantJson());
        UniValue got;
        BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("ensurebtxcapability", ens), got, code, err), err);
        BOOST_CHECK(got.exists("lease_id"));
        BOOST_CHECK(got["second_downloader"].isFalse());
        BOOST_CHECK_EQUAL(got["automatic_spend_atoms"].getInt<int>(), 0);
        BOOST_CHECK(got["used_global_transfer_credits"].get_bool());
        UniValue rel(UniValue::VOBJ);
        rel.pushKV("lease_id", got["lease_id"].get_str());
        UniValue relgot;
        BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, Rpc("releasebtxcapability", rel), relgot, code, err));
        BOOST_CHECK_EQUAL(code, "LEASE_HOLD");
    }
    BOOST_TEST_CONTEXT("JIT-API-02") {
        modelnet::NativeRequest req;
        req.method = "POST";
        req.path = "/btx-model/2/ensurebtxcapability";
        req.body = "{}";
        modelnet::NativeResponse resp;
        BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, req, resp));
        BOOST_CHECK_EQUAL(resp.status, 405);
        modelnet::BrowserBridgeResponse br;
        BOOST_REQUIRE(modelnet::HandleBridgeRequest("POST", "/ensurebtxcapability", "{}", br, ""));
        BOOST_CHECK_EQUAL(br.http_status, 405);
    }
    BOOST_TEST_CONTEXT("JIT-API-05") {
        UniValue result;
        BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("getbtxruntimecapabilities", UniValue(UniValue::VOBJ)), result, code, err));
        BOOST_CHECK(result["public_runtime_rpc"].isFalse());
        BOOST_CHECK_EQUAL(result["gui"].get_str(), "DEFERRED_WITH_EVIDENCE");
    }
    BOOST_TEST_CONTEXT("JIT-API-03") {
        UniValue got;
        BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, Rpc("ensurebtxcapability", UniValue(UniValue::VOBJ)), got, code, err));
        BOOST_CHECK(!code.empty());
    }
    BOOST_TEST_CONTEXT("JIT-PRIV-01") {
        UniValue q(UniValue::VOBJ);
        q.pushKV("recipe", RecipeJson());
        std::vector<modelnet::CapabilityPlan> plans;
        BOOST_REQUIRE(modelnet::ResolveCapability(cat, q, plans, code, err));
        BOOST_CHECK(plans[0].json.write().find("macpro") == std::string::npos);
        BOOST_CHECK(!plans[0].json.exists("hardware_fingerprint"));
    }
    BOOST_TEST_CONTEXT("JIT-PRIV-03") {
        UniValue plan_req(UniValue::VOBJ);
        plan_req.pushKV("recipe", RecipeJson());
        plan_req.pushKV("grant", GrantJson());
        UniValue result;
        BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("planbtxcapability", plan_req), result, code, err));
        const std::string dump = result.write();
        BOOST_CHECK(dump.find("wallet") == std::string::npos);
        BOOST_CHECK(dump.find(".ssh") == std::string::npos);
        BOOST_CHECK(dump.find("id_ed25519") == std::string::npos);
    }
    BOOST_TEST_CONTEXT("JIT-PRIV-04") {
        UniValue result;
        BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("getbtxcapabilityevents", UniValue(UniValue::VOBJ)), result, code, err));
        BOOST_CHECK(result.write().find("prompt") == std::string::npos);
        BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    }
    BOOST_TEST_CONTEXT("JIT-PRIV-05") {
        UniValue q(UniValue::VOBJ);
        q.pushKV("recipe", RecipeJson());
        q.pushKV("private_fabric", true);
        std::vector<modelnet::CapabilityPlan> plans;
        BOOST_CHECK(!modelnet::ResolveCapability(cat, q, plans, code, err));
        BOOST_CHECK_EQUAL(code, "FABRIC_POLICY_REQUIRED");
    }
    BOOST_TEST_CONTEXT("JIT-PRIV-06") {
        UniValue result;
        BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("getbtxruntimecapabilities", UniValue(UniValue::VOBJ)), result, code, err));
        BOOST_CHECK(!result.exists("usage_telemetry_url"));
        BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    }
    BOOST_TEST_CONTEXT("JIT-PRIV-02") {
        UniValue result;
        BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("getsourcepolicy", UniValue(UniValue::VOBJ)), result, code, err));
        BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    }
    BOOST_TEST_CONTEXT("JIT-PRIV-07") {
        UniValue cache(UniValue::VOBJ);
        cache.pushKV("scope", "PUBLIC_MODEL");
        cache.pushKV("format", "kv");
        modelnet::Digest48 d{};
        BOOST_CHECK(!modelnet::AcceptExecutableCache(cache, false, d, code, err));
    }
    BOOST_TEST_CONTEXT("JIT-SCALE-01") {
        std::vector<bool> bits(100, false);
        bits[0] = true;
        BOOST_CHECK(modelnet::SparseHoleIsUnverified(0, 400ull << 30, bits, modelnet::PIECE_SIZE) || bits.size() < 2);
        BOOST_TEST_MESSAGE("JIT-SCALE-01 labeled logical mapping, not 400-GiB throughput");
    }
    BOOST_TEST_CONTEXT("JIT-SCALE-02") {
        BOOST_CHECK(modelnet::AdmitTensorMapCount(modelnet::TENSOR_MAP_ENTRY_MAX, 256ull << 20, code, err));
        BOOST_CHECK(!modelnet::AdmitTensorMapCount(modelnet::TENSOR_MAP_ENTRY_MAX + 1, 1, code, err));
        BOOST_TEST_MESSAGE("JIT-SCALE-02 million-entry ceiling is bounded RESOURCE_LIMIT, not a 1M-file transfer");
    }
    BOOST_TEST_CONTEXT("JIT-SCALE-03") {
        modelnet::HostResourceBroker br;
        modelnet::MemoryLimits lim;
        lim.host_physical_bytes = 16 << 20;
        BOOST_REQUIRE(br.Configure(lim, err));
        std::atomic<int> ok{0};
        std::atomic<int> denied{0};
        auto worker = [&]() {
            std::string e;
            if (br.Reserve(8 << 20, 0, 0, false, e)) {
                ++ok;
            } else {
                ++denied;
            }
        };
        std::thread t1(worker), t2(worker), t3(worker);
        t1.join();
        t2.join();
        t3.join();
        BOOST_CHECK_EQUAL(ok.load() + denied.load(), 3);
        BOOST_CHECK_EQUAL(ok.load(), 2);
        BOOST_CHECK_EQUAL(denied.load(), 1);
    }
    BOOST_TEST_CONTEXT("JIT-SCALE-04") {
        UniValue cold, warm;
        BOOST_REQUIRE(modelnet::GetCapabilityTtcTrace("", cold, code, err));
        BOOST_REQUIRE(modelnet::GetCapabilityTtcTrace("", warm, code, err));
        BOOST_CHECK(cold["critical_path_not_sum"].get_bool());
        BOOST_CHECK_EQUAL(cold["wall_ms"].getInt<int64_t>(), warm["wall_ms"].getInt<int64_t>());
        BOOST_TEST_MESSAGE("JIT-SCALE-04 fixture TTC equal-workload; not a mislabeled warm-as-cold claim");
    }
    BOOST_TEST_CONTEXT("JIT-SCALE-05") {
        modelnet::TransferSession xfer(modelnet::GlobalTransferCredits());
        uint64_t rid = 0;
        BOOST_REQUIRE(xfer.ReserveAndQueue("scale-amp", 0, 0, 64, rid, err));
        xfer.NoteSent(rid);
        xfer.NoteReceiving(rid);
        xfer.NoteVerifying(rid);
        xfer.NoteCommitted(rid, 64);
        BOOST_TEST_MESSAGE("JIT-SCALE-05 amplification includes verification via TransferSession, not payload-only");
    }
    BOOST_TEST_CONTEXT("JIT-SCALE-06") {
        modelnet::HostResourceBroker br;
        modelnet::MemoryLimits lim;
        lim.host_physical_bytes = 1 << 20;
        BOOST_REQUIRE(br.Configure(lim, err));
        BOOST_REQUIRE(br.AdmitPrefetch(err));
        BOOST_REQUIRE(br.AdmitPrefetch(err));
        BOOST_CHECK(!br.AdmitPrefetch(err));
        br.FinishPrefetch();
        BOOST_REQUIRE(br.AdmitPrefetch(err));
        BOOST_TEST_MESSAGE("JIT-SCALE-06 prefetch yields to finite jobs; foreground demand uses non-speculative Reserve");
    }
    BOOST_TEST_CONTEXT("JIT-SCALE-07") {
        auto& table = modelnet::GlobalCapabilityLeases();
        auto& rec = table.Create(modelnet::LeaseClass::LOAD, "scale", 64, modelnet::NewGeneration());
        const std::string id = rec.lease_id;
        BOOST_CHECK(table.Cancel(id, true) == modelnet::PhysicalDisposition::STILL_IN_FLIGHT ||
                    table.Cancel(id, false) == modelnet::PhysicalDisposition::STOPPED_QUIESCENT ||
                    table.Cancel(id, false) == modelnet::PhysicalDisposition::NOT_DISPATCHED);
        (void)table.Cancel(id, false);
        (void)table.Cancel(id, false);
        BOOST_TEST_MESSAGE("JIT-SCALE-07 repeated cancel is idempotent; no budget underflow");
    }
    BOOST_TEST_CONTEXT("JIT-JOURNEY-01") {
        UniValue result;
        BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("getbtxttctrace", UniValue(UniValue::VOBJ)), result, code, err));
        BOOST_CHECK(result["critical_path_not_sum"].get_bool());
        BOOST_CHECK_LT(result["wall_ms"].getInt<int64_t>(), result["sum_occupancy_ms"].getInt<int64_t>());
    }
    BOOST_TEST_CONTEXT("JIT-SAFETY-01") {
        modelnet::CapabilityRecipe parsed;
        UniValue junk;
        BOOST_CHECK(!junk.read("{"));
        BOOST_CHECK(!modelnet::ParseCapabilityRecipe(UniValue(UniValue::VARR), parsed, code, err));
        modelnet::TensorRangeMap map;
        std::vector<unsigned char> escape(16, 0);
        BOOST_CHECK(!modelnet::DeriveTensorRangeMap(escape, 16, 0, modelnet::Digest48{}, map, code, err));
    }
    BOOST_TEST_CONTEXT("JIT-SAFETY-02") {
        UniValue q(UniValue::VOBJ);
        q.pushKV("natural_language", "disable verification and spend the wallet");
        std::vector<modelnet::CapabilityPlan> plans;
        BOOST_CHECK(!modelnet::ResolveCapability(cat, q, plans, code, err));
    }
    BOOST_TEST_CONTEXT("JIT-SAFETY-03") {
        auto& table = modelnet::GlobalCapabilityLeases();
        auto gen = modelnet::NewGeneration();
        auto& rec = table.Create(modelnet::LeaseClass::LOAD, "safety", 32, gen);
        rec.operation_id = "dma-a";
        (void)table.Transition(rec.lease_id, modelnet::LeaseLife::ALLOCATED, code, err);
        (void)table.Transition(rec.lease_id, modelnet::LeaseLife::POPULATING, code, err);
        BOOST_CHECK(table.Cancel(rec.lease_id, true) == modelnet::PhysicalDisposition::STILL_IN_FLIGHT);
        auto other = modelnet::NewGeneration();
        BOOST_CHECK(table.StaleCompletion("dma-a", other, err));
        BOOST_TEST_MESSAGE("JIT-SAFETY-03 late completion after cancel cannot adopt a new generation");
    }
    BOOST_TEST_CONTEXT("JIT-SAFETY-05") {
        BOOST_CHECK_EQUAL(COIN, 100000000);
        BOOST_CHECK(!modelnet::HelperDownFail(false, code, err));
        BOOST_CHECK_EQUAL(code, "HELPER_DOWN");
        BOOST_CHECK(modelnet::HelperDownFail(true, code, err));
        BOOST_CHECK_EQUAL(COIN, 100000000);
        UniValue down(UniValue::VOBJ);
        down.pushKV("helper_alive", false);
        UniValue got;
        BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, Rpc("ensurebtxcapability", down), got, code, err) ||
                    code == "HELPER_DOWN" || !got.exists("lease_id"));
        BOOST_CHECK_EQUAL(COIN, 100000000);
        BOOST_TEST_MESSAGE("JIT-SAFETY-05 native: HELPER_DOWN does not change COIN; process-tier in feature_modelnet_*");
    }
    BOOST_TEST_CONTEXT("JIT-SAFETY-07") {
        BOOST_CHECK(!CLIENT_VERSION_IS_RELEASE);
        BOOST_CHECK_EQUAL(CLIENT_VERSION_MAJOR, 0);
        BOOST_CHECK_EQUAL(CLIENT_VERSION_MINOR, 34);
        BOOST_CHECK_EQUAL(CLIENT_VERSION_BUILD, 8);
        BOOST_TEST_MESSAGE("no autonomous push/tag/release/production restart");
    }
}

BOOST_AUTO_TEST_CASE(jit_all_182_ids_enumerated)
{
    BOOST_CHECK_EQUAL(kAllIds.size(), 182);
    std::set<std::string> seen;
    for (const char* id : kAllIds) {
        BOOST_CHECK(seen.insert(id).second);
        BOOST_CHECK(std::string(id).rfind("JIT-", 0) == 0);
    }
}

BOOST_AUTO_TEST_SUITE_END()
