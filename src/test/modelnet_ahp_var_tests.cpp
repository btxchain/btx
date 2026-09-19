// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Lane C BTX-AHP-001 VAR.
// AHP-VAR-01  ahp_var_01_explicit_selection_wins
// AHP-VAR-02  ahp_var_02_no_vendor_preference
// AHP-VAR-03  ahp_var_03_memory_feasibility
// AHP-VAR-04  ahp_var_04_unknown_compatibility
// AHP-VAR-05  ahp_var_05_dependency_cycle_and_depth
// AHP-VAR-06  ahp_var_06_variant_resource_mismatch
// AHP-VAR-07  ahp_var_07_partial_selection
// AHP-VAR-08  ahp_var_08_model_less_bounty
// Do not call production helper, wallet, or production btxd. Isolated
// DispatchHelperRpc against a temp catalog is in-process only.

#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/package_acquisition.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_ahp_var_tests, BasicTestingSetup)

namespace {

std::string HexId(char nibble)
{
    return std::string(96, nibble);
}

UniValue Resource(const std::string& id, const std::string& kind = "MODEL")
{
    UniValue r(UniValue::VOBJ);
    r.pushKV("kind", kind);
    r.pushKV("id", id);
    r.pushKV("format", "GGUF");
    return r;
}

UniValue Variant(const std::string& vid, const std::string& rid, const std::vector<std::string>& backends)
{
    UniValue v(UniValue::VOBJ);
    v.pushKV("variant_id", vid);
    v.pushKV("name", vid);
    v.pushKV("resource_id", rid);
    v.pushKV("format", "GGUF");
    UniValue be(UniValue::VARR);
    for (const auto& b : backends) be.push_back(b);
    UniValue c(UniValue::VOBJ);
    c.pushKV("backends", be);
    UniValue arch(UniValue::VARR);
    arch.push_back("x86_64");
    arch.push_back("aarch64");
    c.pushKV("architectures", arch);
    v.pushKV("compatibility", c);
    return v;
}

UniValue FamilyCore(const std::vector<UniValue>& variants, const std::string& default_variant)
{
    UniValue core(UniValue::VOBJ);
    core.pushKV("version", 2);
    core.pushKV("network", "REGTEST");
    core.pushKV("package_type", "VARIANT_INDEX");
    core.pushKV("label", "var-family");
    UniValue resources(UniValue::VARR);
    resources.push_back(Resource(HexId('a')));
    resources.push_back(Resource(HexId('b')));
    core.pushKV("resources", resources);
    UniValue vs(UniValue::VARR);
    for (const auto& v : variants) vs.push_back(v);
    core.pushKV("variants", vs);
    UniValue acq(UniValue::VOBJ);
    if (!default_variant.empty()) acq.pushKV("default_variant", default_variant);
    acq.pushKV("retrieval_mode", "FREE_ONLY");
    acq.pushKV("source_policy", "NATIVE_ONLY");
    UniValue ah(UniValue::VOBJ);
    ah.pushKV("acquisition", acq);
    core.pushKV("agent_handoff", ah);
    return core;
}

UniValue CapableObs()
{
    UniValue obs(UniValue::VOBJ);
    UniValue be(UniValue::VARR);
    be.push_back("cpu");
    be.push_back("cuda");
    be.push_back("rocm");
    be.push_back("metal");
    obs.pushKV("backends", be);
    obs.pushKV("architecture", "x86_64");
    UniValue formats(UniValue::VARR);
    formats.push_back("GGUF");
    obs.pushKV("supported_formats", formats);
    return obs;
}

std::string Dec(uint64_t n) { return std::to_string(n); }

void SetMemEstimate(UniValue& variant, const std::string& min_ram, const std::string& weight,
                    const std::string& kv, const std::string& runtime)
{
    UniValue c = variant["compatibility"];
    c.pushKV("minimum_ram_bytes", min_ram);
    c.pushKV("weight_bytes", weight);
    c.pushKV("kv_overhead_bytes", kv);
    c.pushKV("runtime_overhead_bytes", runtime);
    variant.pushKV("compatibility", c);
}

std::string ChainId(int i)
{
    std::string s(96, '0');
    s.back() = static_cast<char>('0' + i);
    return s;
}

fs::path AgentPackageDir()
{
#ifdef MODELNET_AHP_FIXTURE_DIR
    return fs::PathFromString(MODELNET_AHP_FIXTURE_DIR);
#else
    return fs::PathFromString(std::string{__FILE__}).parent_path() / "data" / "agent-package";
#endif
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

} // namespace

BOOST_AUTO_TEST_CASE(ahp_var_01_explicit_selection_wins)
{
    const auto pub = Variant("pub-rec", HexId('a'), {"cpu", "cuda", "rocm", "metal"});
    const auto user = Variant("user-pick", HexId('b'), {"cpu", "cuda", "rocm", "metal"});
    const UniValue core = FamilyCore({pub, user}, "pub-rec");
    UniValue obs = CapableObs();
    obs.pushKV("explicit_variant", "user-pick");

    std::string vid, code, err;
    BOOST_REQUIRE(modelnet::SelectPackageVariant(core, obs, vid, code, err));
    BOOST_CHECK_EQUAL(vid, "user-pick");
    BOOST_CHECK(err.empty());

    obs.pushKV("preferred_variant", "pub-rec");
    BOOST_REQUIRE(modelnet::SelectPackageVariant(core, obs, vid, code, err));
    BOOST_CHECK_EQUAL(vid, "user-pick");
}

BOOST_AUTO_TEST_CASE(ahp_var_02_no_vendor_preference)
{
    const std::vector<std::string> all{"cpu", "cuda", "rocm", "metal"};
    const auto cuda_first = Variant("cuda-first", HexId('a'), all);
    const auto cpu_ok = Variant("cpu-ok", HexId('b'), all);
    const UniValue obs = CapableObs();
    std::string a, b, code, err;

    const UniValue order_cuda = FamilyCore({cuda_first, cpu_ok}, "cuda-first");
    BOOST_REQUIRE(modelnet::SelectPackageVariant(order_cuda, obs, a, code, err));
    const UniValue order_cpu = FamilyCore({cpu_ok, cuda_first}, "cuda-first");
    BOOST_REQUIRE(modelnet::SelectPackageVariant(order_cpu, obs, b, code, err));
    BOOST_CHECK_EQUAL(a, b);
    BOOST_CHECK_EQUAL(a, "cpu-ok");

    const auto aaa_cuda = Variant("aaa-cuda", HexId('a'), all);
    const auto zzz_cpu = Variant("zzz-cpu", HexId('b'), all);
    std::string c, d;
    BOOST_REQUIRE(modelnet::SelectPackageVariant(FamilyCore({zzz_cpu, aaa_cuda}, ""), obs, c, code, err));
    BOOST_REQUIRE(modelnet::SelectPackageVariant(FamilyCore({aaa_cuda, zzz_cpu}, ""), obs, d, code, err));
    BOOST_CHECK_EQUAL(c, d);
    BOOST_CHECK_EQUAL(c, "aaa-cuda");
}

BOOST_AUTO_TEST_CASE(ahp_var_08_model_less_bounty)
{
    UniValue core(UniValue::VOBJ);
    core.pushKV("version", 2);
    core.pushKV("network", "REGTEST");
    core.pushKV("package_type", "BOUNTY");
    core.pushKV("label", "no winning model");
    core.pushKV("resources", UniValue(UniValue::VARR));
    core.pushKV("variants", UniValue(UniValue::VARR));
    UniValue econ(UniValue::VARR);
    UniValue bref(UniValue::VOBJ);
    bref.pushKV("kind", "BOUNTY");
    bref.pushKV("id", HexId('c'));
    econ.push_back(bref);
    core.pushKV("economy_refs", econ);

    std::string vid, code, err;
    BOOST_REQUIRE(modelnet::SelectPackageVariant(core, UniValue(UniValue::VOBJ), vid, code, err));
    BOOST_CHECK(vid.empty());
    BOOST_CHECK(err.empty());

    const fs::path dest = m_path_root / "bounty-must-not-materialize";
    UniValue policy(UniValue::VOBJ);
    policy.pushKV("destination", dest.utf8string());
    modelnet::AcquisitionPlan plan;
    BOOST_REQUIRE(modelnet::PlanBtxAcquisition(core, policy, plan, code, err));
    BOOST_CHECK(plan.variant_id.empty());
    BOOST_CHECK(plan.resource_ids.empty());
    BOOST_CHECK_EQUAL(plan.retrieval_mode, "FREE_ONLY");
    BOOST_CHECK(!fs::exists(dest));
    BOOST_CHECK(!plan.json.exists("authorization_ref"));
}

BOOST_AUTO_TEST_CASE(ahp_var_rejects_cycle_missing_duplicate)
{
    std::string vid, code, err;
    {
        UniValue core = FamilyCore(
            {Variant("ok", HexId('a'), {"cpu"})}, "");
        UniValue resources(UniValue::VARR);
        UniValue a = Resource(HexId('a'));
        UniValue deps(UniValue::VARR);
        deps.push_back(HexId('b'));
        a.pushKV("dependencies", deps);
        UniValue b = Resource(HexId('b'));
        UniValue bdeps(UniValue::VARR);
        bdeps.push_back(HexId('a'));
        b.pushKV("dependencies", bdeps);
        resources.push_back(a);
        resources.push_back(b);
        core.pushKV("resources", resources);
        BOOST_CHECK(!modelnet::SelectPackageVariant(core, CapableObs(), vid, code, err));
        BOOST_CHECK_EQUAL(code, "DEPENDENCY_CYCLE");
    }
    {
        UniValue core = FamilyCore({Variant("missing", HexId('d'), {"cpu"})}, "");
        BOOST_CHECK(!modelnet::SelectPackageVariant(core, CapableObs(), vid, code, err));
        BOOST_CHECK_EQUAL(code, "MISSING_RESOURCE");
    }
    {
        UniValue core = FamilyCore(
            {Variant("ok", HexId('a'), {"cpu"})}, "");
        UniValue resources(UniValue::VARR);
        resources.push_back(Resource(HexId('a')));
        UniValue dup = Resource(HexId('a'));
        dup.pushKV("label", "other commitment");
        resources.push_back(dup);
        core.pushKV("resources", resources);
        BOOST_CHECK(!modelnet::SelectPackageVariant(core, CapableObs(), vid, code, err));
        BOOST_CHECK_EQUAL(code, "DUPLICATE_ID");
    }
}

BOOST_AUTO_TEST_CASE(ahp_var_no_compatible_does_not_invent)
{
    const auto cuda_only = Variant("cuda-only", HexId('a'), {"cuda"});
    UniValue obs(UniValue::VOBJ);
    UniValue be(UniValue::VARR);
    be.push_back("cpu");
    obs.pushKV("backends", be);
    std::string vid, code, err;
    BOOST_CHECK(!modelnet::SelectPackageVariant(FamilyCore({cuda_only}, "cuda-only"), obs, vid, code, err));
    BOOST_CHECK_EQUAL(code, "NO_COMPATIBLE_VARIANT");
    BOOST_CHECK(vid.empty());
}

BOOST_AUTO_TEST_CASE(ahp_var_03_memory_feasibility)
{
    // Effective RAM = max(minimum_ram_bytes, weight+kv+runtime). Weight-file
    // size_bytes alone is never a guaranteed fit.
    constexpr uint64_t k512MiB = 536870912ull;
    constexpr uint64_t k1GiB = 1073741824ull;
    constexpr uint64_t k1_5GiB = 1610612736ull;
    constexpr uint64_t k3GiB = 3221225472ull;
    constexpr uint64_t k8GiB = 8589934592ull;

    const std::vector<std::string> all{"cpu", "cuda", "rocm", "metal"};
    UniValue small = Variant("small", HexId('a'), all);
    SetMemEstimate(small, Dec(k1GiB), Dec(k512MiB), Dec(k1GiB), Dec(k512MiB));
    UniValue oversized = Variant("oversized", HexId('b'), all);
    SetMemEstimate(oversized, Dec(k8GiB), Dec(k512MiB), "0", "0");

    UniValue core = FamilyCore({small, oversized}, "");
    UniValue ra = Resource(HexId('a'));
    ra.pushKV("size_bytes", Dec(k512MiB));
    UniValue rb = Resource(HexId('b'));
    rb.pushKV("size_bytes", Dec(k512MiB));
    UniValue resources(UniValue::VARR);
    resources.push_back(ra);
    resources.push_back(rb);
    core.pushKV("resources", resources);

    std::string vid, code, err;
    UniValue obs_fit = CapableObs();
    obs_fit.pushKV("available_ram_bytes", Dec(k3GiB));
    BOOST_REQUIRE_MESSAGE(modelnet::SelectPackageVariant(core, obs_fit, vid, code, err), err);
    BOOST_CHECK_EQUAL(vid, "small");

    UniValue obs_tight = CapableObs();
    obs_tight.pushKV("available_ram_bytes", Dec(k1_5GiB));
    BOOST_CHECK(!modelnet::SelectPackageVariant(core, obs_tight, vid, code, err));
    BOOST_CHECK_EQUAL(code, "NO_COMPATIBLE_VARIANT");
    BOOST_CHECK(vid.empty());
}

BOOST_AUTO_TEST_CASE(ahp_var_04_unknown_compatibility)
{
    // Unknown format is enough. An adapter label without an installed adapter
    // is runtime-side, not variant selection.
    UniValue exotic = Variant("exotic", HexId('a'), {"cpu", "cuda", "rocm", "metal"});
    exotic.pushKV("format", "EXOTIC");
    std::string vid, code, err;
    BOOST_CHECK(!modelnet::SelectPackageVariant(FamilyCore({exotic}, "exotic"), CapableObs(), vid, code, err));
    BOOST_CHECK_EQUAL(code, "NO_COMPATIBLE_VARIANT");
    BOOST_CHECK(vid.empty());
}

BOOST_AUTO_TEST_CASE(ahp_var_05_dependency_cycle_and_depth)
{
    std::string vid, code, err;
    auto MakeChain = [](int n) {
        UniValue core(UniValue::VOBJ);
        core.pushKV("version", 2);
        core.pushKV("network", "REGTEST");
        core.pushKV("package_type", "VARIANT_INDEX");
        core.pushKV("label", "depth-chain");
        UniValue resources(UniValue::VARR);
        for (int i = 0; i < n; ++i) {
            UniValue r = Resource(ChainId(i));
            if (i + 1 < n) {
                UniValue deps(UniValue::VARR);
                deps.push_back(ChainId(i + 1));
                r.pushKV("dependencies", deps);
            }
            resources.push_back(r);
        }
        core.pushKV("resources", resources);
        UniValue vs(UniValue::VARR);
        vs.push_back(Variant("deep", ChainId(0), {"cpu"}));
        core.pushKV("variants", vs);
        UniValue acq(UniValue::VOBJ);
        acq.pushKV("retrieval_mode", "FREE_ONLY");
        acq.pushKV("source_policy", "NATIVE_ONLY");
        UniValue ah(UniValue::VOBJ);
        ah.pushKV("acquisition", acq);
        core.pushKV("agent_handoff", ah);
        return core;
    };
    {
        // Depth bound is 8. Nine MODEL resources (root + 8 hops) are at the
        // bound; ten resources exceed it.
        BOOST_REQUIRE_MESSAGE(modelnet::SelectPackageVariant(MakeChain(9), CapableObs(), vid, code, err), err);
        BOOST_CHECK_EQUAL(vid, "deep");
        BOOST_CHECK(!modelnet::SelectPackageVariant(MakeChain(10), CapableObs(), vid, code, err));
        BOOST_CHECK_EQUAL(code, "DEPENDENCY_CYCLE");
        BOOST_CHECK_EQUAL(err, "dependency depth exceeded");
    }
    {
        UniValue core = FamilyCore({Variant("missing", HexId('d'), {"cpu"})}, "");
        BOOST_CHECK(!modelnet::SelectPackageVariant(core, CapableObs(), vid, code, err));
        BOOST_CHECK_EQUAL(code, "MISSING_RESOURCE");
    }
}

BOOST_AUTO_TEST_CASE(ahp_var_06_variant_resource_mismatch)
{
    std::string vid, code, err;
    {
        UniValue core = FamilyCore({Variant("artifact", HexId('a'), {"cpu"})}, "");
        UniValue resources(UniValue::VARR);
        resources.push_back(Resource(HexId('a'), "ARTIFACT"));
        resources.push_back(Resource(HexId('b')));
        core.pushKV("resources", resources);
        BOOST_CHECK(!modelnet::SelectPackageVariant(core, CapableObs(), vid, code, err));
        BOOST_CHECK_EQUAL(code, "MISSING_RESOURCE");
    }
    {
        UniValue core = FamilyCore({Variant("absent", HexId('d'), {"cpu"})}, "");
        BOOST_CHECK(!modelnet::SelectPackageVariant(core, CapableObs(), vid, code, err));
        BOOST_CHECK_EQUAL(code, "MISSING_RESOURCE");
    }
}

BOOST_AUTO_TEST_CASE(ahp_var_07_partial_selection)
{
    // Tokenizer ARTIFACT is a real dependency of the MODEL. The plan may name
    // both ids. Execute returning SELECTION_READY is helper-side, not this planner.
    UniValue core = FamilyCore({Variant("demo-q4", HexId('a'), {"cpu", "cuda", "rocm", "metal"})}, "demo-q4");
    UniValue model = Resource(HexId('a'));
    UniValue deps(UniValue::VARR);
    deps.push_back(HexId('c'));
    model.pushKV("dependencies", deps);
    UniValue tok = Resource(HexId('c'), "ARTIFACT");
    tok.pushKV("label", "tokenizer");
    UniValue resources(UniValue::VARR);
    resources.push_back(model);
    resources.push_back(tok);
    core.pushKV("resources", resources);

    const fs::path dest = m_path_root / "var-07-tokenizer-only";
    UniValue policy(UniValue::VOBJ);
    policy.pushKV("destination", dest.utf8string());
    policy.pushKV("explicit_variant", "demo-q4");

    modelnet::AcquisitionPlan plan;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxAcquisition(core, policy, plan, code, err), err);
    BOOST_REQUIRE_EQUAL(plan.resource_ids.size(), 2);
    BOOST_CHECK_EQUAL(plan.resource_ids[0], HexId('a'));
    BOOST_CHECK_EQUAL(plan.resource_ids[1], HexId('c'));
    BOOST_CHECK(!plan.json.exists("state"));
    BOOST_CHECK(!plan.json.exists("ready_state"));
    BOOST_CHECK(plan.json.write().find("MODEL_READY") == std::string::npos);
    BOOST_CHECK_EQUAL(plan.retrieval_mode, "FREE_ONLY");
    BOOST_CHECK(!fs::exists(dest));

    const fs::path tmp = m_path_root / "var-07-helper";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    UniValue arg(UniValue::VOBJ);
    arg.pushKV("path", fs::PathToString(AgentPackageDir() / "model-agent.btx"));
    UniValue result;
    std::string rpc_code, rpc_err;
    BOOST_REQUIRE_MESSAGE(
        modelnet::DispatchHelperRpc(cat, Rpc("planbtxacquisition", arg), result, rpc_code, rpc_err), rpc_err);
    UniValue ex(UniValue::VOBJ);
    ex.pushKV("plan_id", result["plan_id"].get_str());
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE_MESSAGE(
        modelnet::DispatchHelperRpc(cat, Rpc("executebtxacquisition", ex), result, rpc_code, rpc_err), rpc_err);
    BOOST_CHECK_EQUAL(result["state"].get_str(), "SELECTION_READY");
    BOOST_CHECK(result["state"].get_str() != "MODEL_READY");
    BOOST_CHECK(!result["file_bytes_verified"].get_bool());
    BOOST_CHECK(!result["manifest_verified"].get_bool());
    BOOST_TEST_MESSAGE("AHP-VAR-07 remainder NOT_RUN: MODEL_READY after canonical completeness needs helper materialize");
}

BOOST_AUTO_TEST_SUITE_END()
