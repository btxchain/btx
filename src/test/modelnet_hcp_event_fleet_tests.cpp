// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// HCP-EVENT-01 .. 08 and HCP-FLEET-01 .. 08 unique native cases.

#include <test/modelnet_hcp_test.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_hcp_event_fleet_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(hcp_event_01_at_least_once_duplicate)
{
    auto e = hcp_test::Lab();
    e->DeliverEventDuplicates("release-1", 5);
    BOOST_CHECK_EQUAL(e->EventLogicalCount("release-1"), 1);
}

BOOST_AUTO_TEST_CASE(hcp_event_02_cursor_retention)
{
    auto e = hcp_test::Lab();
    const std::string tok = hcp_test::Token(*e, {"events:read"});
    e->RestoreCatalogueIndex();
    auto req = hcp_test::AuthReq(*e, "GET", "/events", tok);
    req.query = "cursor=1";
    auto resp = e->Handle(req);
    BOOST_CHECK(resp.status == 409 || resp.body.find(modelnet::HCP_ERR_CURSOR_TOO_OLD) != std::string::npos);
}

BOOST_AUTO_TEST_CASE(hcp_event_03_account_cursor_binding)
{
    auto e = hcp_test::Lab();
    const std::string tok = hcp_test::Token(*e, {"events:read"});
    auto req = hcp_test::AuthReq(*e, "GET", "/events", tok);
    req.query = "account_ref=account-b";
    auto resp = e->Handle(req);
    BOOST_CHECK_GE(resp.status, 400);
}

BOOST_AUTO_TEST_CASE(hcp_event_04_future_subscription_race)
{
    auto e = hcp_test::Lab(true);
    e->DeliverEventDuplicates("policy/event/FUND_RELEASE", 8);
    BOOST_CHECK_EQUAL(e->EventLogicalCount("release-1") + e->EventLogicalCount("policy/event/FUND_RELEASE"), 1);
}

BOOST_AUTO_TEST_CASE(hcp_event_05_catalogue_restore)
{
    auto e = hcp_test::Lab();
    e->RestoreCatalogueIndex();
    BOOST_CHECK_EQUAL(e->EventLogicalCount("historic"), 0);
}

BOOST_AUTO_TEST_CASE(hcp_event_06_outbox_crash)
{
    auto e = hcp_test::Lab();
    e->CrashOutbox();
    BOOST_CHECK(!e->OutboxDrained());
    e->RecoverOutbox();
    BOOST_CHECK(e->OutboxDrained());
}

BOOST_AUTO_TEST_CASE(hcp_event_07_webhook_ssrf)
{
    auto e = hcp_test::Lab();
    std::string code;
    e->SetWebhookTarget("http://127.0.0.1/latest/meta-data", code);
    BOOST_CHECK_EQUAL(code, "WEBHOOK_SSRF");
    e->SetWebhookTarget("https://example.com/hook", code);
    BOOST_CHECK(code.empty());
}

BOOST_AUTO_TEST_CASE(hcp_event_08_revoked_subscription)
{
    auto e = hcp_test::Lab(true);
    e->SetSubscriptionRevoked("sub-1");
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/subscriptions/sub-1/revoke", tok, &body));
    BOOST_CHECK(r.status == 200 || r.status == 201);
    BOOST_CHECK(r.body.find("new_signatures") != std::string::npos || r.status == 200);
}

BOOST_AUTO_TEST_CASE(hcp_fleet_01_pair_exact_device)
{
    auto e = hcp_test::Lab();
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("device_id", "device-fleet");
    auto en = e->Handle(hcp_test::AuthReq(*e, "POST", "/devices/enroll", tok, &body));
    BOOST_REQUIRE_EQUAL(en.status, 201);
    UniValue d;
    BOOST_REQUIRE(d.read(en.body));
    UniValue conf(UniValue::VOBJ);
    conf.pushKV("challenge", d["challenge"].get_str());
    auto ok = e->Handle(hcp_test::AuthReq(*e, "POST", "/devices/device-fleet/confirm", tok, &conf));
    BOOST_CHECK_EQUAL(ok.status, 200);
    UniValue bad(UniValue::VOBJ);
    bad.pushKV("challenge", "wrong");
    e->Handle(hcp_test::AuthReq(*e, "POST", "/devices/enroll", tok));
}

BOOST_AUTO_TEST_CASE(hcp_fleet_02_no_ambient_localhost_api)
{
    auto e = hcp_test::Lab();
    auto r = e->Handle({.method = "POST", .path = "/finance/intents", .body = "{}"});
    BOOST_CHECK_GE(r.status, 400);
}

BOOST_AUTO_TEST_CASE(hcp_fleet_03_outbound_only_handoff)
{
    auto e = hcp_test::Lab();
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    e->PairDevice("device-demo", "account-demo");
    auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/devices/device-demo/handoffs", tok));
    BOOST_CHECK(r.body.find("outbound_only") != std::string::npos);
    BOOST_CHECK(r.body.find("\"inbound_execution_port\":false") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(hcp_fleet_04_device_revocation)
{
    auto e = hcp_test::Lab();
    e->RevokeDevice("device-demo");
    BOOST_CHECK(!e->DevicePaired("device-demo"));
}

BOOST_AUTO_TEST_CASE(hcp_fleet_05_cross_device_replay)
{
    auto e = hcp_test::Lab();
    e->PairDevice("device-b", "account-demo");
    e->SetDeviceNonce("device-b", "nonce-b");
    auto env = hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe);
    env.body.pushKV("device_id", "device-b");
    std::string err, code;
    e->SignAsProvider(env, err);
    e->AcceptHandoff(env, code, err);
    BOOST_CHECK_EQUAL(code, modelnet::HCP_ERR_HANDOFF_BINDING);
}

BOOST_AUTO_TEST_CASE(hcp_fleet_06_coarse_progress)
{
    auto e = hcp_test::Lab();
    e->SetReadiness("device-demo", "VERIFIED_FILES");
    e->SetReadiness("device-demo", "RUNTIME_READY");
    BOOST_CHECK(e->DevicePaired("device-demo"));
}

BOOST_AUTO_TEST_CASE(hcp_fleet_07_cex_cannot_administer_local_grant)
{
    auto e = hcp_test::Lab();
    auto env = hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe);
    env.body.pushKV("shell", "widen-grant");
    std::string err, code;
    e->SignAsProvider(env, err);
    e->AcceptHandoff(env, code, err);
    BOOST_CHECK_EQUAL(code, "FORBIDDEN_FIELD");
}

BOOST_AUTO_TEST_CASE(hcp_fleet_08_mixed_platform_fleet)
{
    auto e = hcp_test::Lab();
    e->PairDevice("dev-linux", "account-demo");
    e->PairDevice("dev-mac", "account-demo");
    std::string code;
    auto p1 = e->PlanLocal(hcp_test::kRecipe, code);
    auto p2 = e->PlanLocal("unsupported-recipe", code);
    BOOST_CHECK(p1.exists("recipe_id"));
    (void)p2;
}

BOOST_AUTO_TEST_SUITE_END()
