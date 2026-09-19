// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// HCP-LOCAL-01 .. HCP-LOCAL-08 unique native cases.

#include <test/modelnet_hcp_test.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_hcp_local_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(hcp_local_01_resident_base_reuse)
{
    auto e = hcp_test::Lab();
    e->PutResidentBase("base");
    e->PutLanSource("adapter", 40);
    e->PutInternetSource("hint", 4000);
    std::string code;
    auto plan = e->PlanLocal(hcp_test::kRecipe, code);
    BOOST_CHECK(!plan["base_redownload"].isTrue());
    BOOST_CHECK(!plan["inventory_reported"].isTrue());
}

BOOST_AUTO_TEST_CASE(hcp_local_02_faster_path_not_fixed_rank)
{
    auto e = hcp_test::Lab();
    e->PutLanSource("lan", 10);
    e->PutInternetSource("net", 5000);
    std::string code;
    auto plan = e->PlanLocal(hcp_test::kRecipe, code);
    BOOST_CHECK(!plan["fixed_rank_hierarchy"].isTrue());
    BOOST_CHECK(plan["selected_source"].get_str().find("lan") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(hcp_local_03_runtime_trust)
{
    auto e = hcp_test::Lab();
    auto env = hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe);
    UniValue pkg = env.body["package"];
    pkg.pushKV("download_url", "https://evil.example/runtime.exe");
    env.body.pushKV("package", pkg);
    std::string err, code;
    e->SignAsProvider(env, err);
    e->AcceptHandoff(env, code, err);
    BOOST_CHECK(code == modelnet::HCP_ERR_SOFTWARE_TRUST || code == "FORBIDDEN_FIELD");
}

BOOST_AUTO_TEST_CASE(hcp_local_04_sparse_missing_extent)
{
    auto e = hcp_test::Lab();
    e->SetMissingExtent(true);
    UniValue out;
    std::string code;
    BOOST_CHECK(!e->EnsureLocal(hcp_test::kRecipe, out, code));
    BOOST_CHECK_EQUAL(code, "UNVERIFIED_RANGE");
    BOOST_CHECK(!out["zero_fill"].isTrue());
}

BOOST_AUTO_TEST_CASE(hcp_local_05_readiness_distinction)
{
    auto e = hcp_test::Lab();
    e->SetRuntimeWarmupFail(true);
    UniValue out;
    std::string code;
    BOOST_REQUIRE(e->EnsureLocal(hcp_test::kRecipe, out, code));
    BOOST_CHECK(out["transfer_complete"].isTrue());
    BOOST_CHECK(!out["runtime_ready"].isTrue());
}

BOOST_AUTO_TEST_CASE(hcp_local_06_cancel_under_dma)
{
    auto e = hcp_test::Lab();
    e->SetDmaActive(true);
    UniValue out;
    std::string code;
    BOOST_CHECK(!e->EnsureLocal(hcp_test::kRecipe, out, code));
    BOOST_CHECK_EQUAL(code, "LEASE_FENCE");
    BOOST_CHECK(out["lease_retained"].isTrue());
    e->FenceDma();
    BOOST_REQUIRE(e->EnsureLocal(hcp_test::kRecipe, out, code));
}

BOOST_AUTO_TEST_CASE(hcp_local_07_private_state_containment)
{
    auto e = hcp_test::Lab();
    e->SetPrivatePrompt("SECRET_PROMPT_TEXT");
    e->SetPrivateKv("SECRET_KV");
    e->SetReporting(true);
    auto exp = e->ExportPublic(false);
    const std::string dump = exp.write();
    BOOST_CHECK(dump.find("SECRET_PROMPT_TEXT") == std::string::npos);
    BOOST_CHECK(dump.find("SECRET_KV") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(hcp_local_08_no_remote_inference_shortcut)
{
    auto e = hcp_test::Lab();
    UniValue out;
    std::string code;
    BOOST_REQUIRE(e->EnsureLocal(hcp_test::kRecipe, out, code));
    BOOST_CHECK(!out["remote_inference"].isTrue());
}

BOOST_AUTO_TEST_SUITE_END()
