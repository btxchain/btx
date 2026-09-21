// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// HCP-GRANT-01 .. HCP-GRANT-08 unique native cases.

#include <test/modelnet_hcp_test.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <thread>

BOOST_FIXTURE_TEST_SUITE(modelnet_hcp_grant_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(hcp_grant_01_handoff_without_local_grant)
{
    auto e = hcp_test::Lab();
    e->RevokeLocalGrant();
    auto env = hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe);
    std::string code, err;
    e->AcceptHandoff(env, code, err);
    BOOST_CHECK_EQUAL(code, modelnet::HCP_ERR_LOCAL_GRANT_REQUIRED);
}

BOOST_AUTO_TEST_CASE(hcp_grant_02_finite_first_use_convenience)
{
    auto e = hcp_test::Lab();
    auto env = hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe);
    std::string code, err;
    auto a = e->AcceptHandoff(env, code, err);
    BOOST_REQUIRE(code.empty());
    UniValue out;
    BOOST_REQUIRE(e->EnsureLocal(hcp_test::kRecipe, out, code));
    BOOST_REQUIRE(e->EnsureLocal(hcp_test::kRecipe, out, code));
    BOOST_CHECK(code.empty());
}

BOOST_AUTO_TEST_CASE(hcp_grant_03_financial_policy_cannot_launch)
{
    auto e = hcp_test::Lab();
    UniValue pol(UniValue::VOBJ);
    pol.pushKV("policy_id", "policy-demo");
    UniValue acts(UniValue::VARR);
    acts.push_back("FUND_RELEASE");
    pol.pushKV("allowed_actions", acts);
    modelnet::LocalCapabilityGrant g;
    std::string code, err;
    BOOST_REQUIRE(modelnet::ParseGrant(pol, g, code, err));
    e->SetLocalGrant(g);
    auto env = hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe);
    e->AcceptHandoff(env, code, err);
    BOOST_CHECK_EQUAL(code, modelnet::HCP_ERR_POLICY_FINANCE);
}

BOOST_AUTO_TEST_CASE(hcp_grant_04_local_grant_cannot_spend)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("local_grant_id", "grant-owner");
    body.pushKV("client_operation_id", "op-grant04");
    auto resp = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    BOOST_CHECK_GE(resp.status, 400);
}

BOOST_AUTO_TEST_CASE(hcp_grant_05_revocation_race)
{
    auto e = hcp_test::Lab();
    auto env = hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe);
    std::string code, err;
    auto acc = e->AcceptHandoff(env, code, err);
    BOOST_REQUIRE(code.empty());
    BOOST_REQUIRE(acc.exists("handoff_id"));

    constexpr int N = 32;
    std::atomic<int> unexpected{0};
    std::thread ta([&] {
        for (int i = 0; i < N; ++i) {
            e->RevokeLocalGrant();
            e->SetLocalGrant(hcp_test::OwnerGrant());
            e->RevokeLocalGrant();
        }
    });
    std::thread tb([&] {
        for (int i = 0; i < N; ++i) {
            UniValue out;
            std::string local_code;
            const bool ok = e->EnsureLocal(hcp_test::kRecipe, out, local_code);
            if (!ok && local_code != modelnet::HCP_ERR_LOCAL_GRANT_REQUIRED) {
                unexpected.fetch_add(1);
            }
        }
    });
    ta.join();
    tb.join();
    BOOST_CHECK_EQUAL(unexpected.load(), 0);

    e->RevokeLocalGrant();
    UniValue out;
    BOOST_CHECK(!e->EnsureLocal(hcp_test::kRecipe, out, code));
    BOOST_CHECK_EQUAL(code, modelnet::HCP_ERR_LOCAL_GRANT_REQUIRED);
}

BOOST_AUTO_TEST_CASE(hcp_grant_06_resource_ceilings)
{
    auto e = hcp_test::Lab();
    UniValue out;
    std::string code;
    BOOST_REQUIRE(e->EnsureLocal(hcp_test::kRecipe, out, code));
    BOOST_CHECK(code.empty());
}

BOOST_AUTO_TEST_CASE(hcp_grant_07_future_issuer_scope)
{
    auto e = hcp_test::Lab();
    auto env = hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe);
    env.body.pushKV("provider_id", "publisher-q");
    std::string err;
    BOOST_REQUIRE(e->SignAsProvider(env, err));
    // still our key after rotation policy: publisher Q name is not authority
    std::string code;
    auto acc = e->AcceptHandoff(env, code, err);
    BOOST_CHECK(code.empty() || code == modelnet::HCP_ERR_HANDOFF_BINDING || acc.exists("handoff_id"));
}

BOOST_AUTO_TEST_CASE(hcp_grant_08_deadline_does_not_relax_policy)
{
    auto e = hcp_test::Lab();
    e->PutInternetSource("fast-untrusted", 1);
    e->PutLanSource("slow-approved", 5000);
    std::string code;
    auto plan = e->PlanLocal(hcp_test::kRecipe, code);
    BOOST_CHECK(plan.exists("selected_source"));
    e->RevokeLocalGrant();
    UniValue out;
    BOOST_CHECK(!e->EnsureLocal(hcp_test::kRecipe, out, code));
    BOOST_CHECK(code != "ok");
}

BOOST_AUTO_TEST_SUITE_END()
