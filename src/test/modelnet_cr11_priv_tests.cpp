// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Unique native Cognitive Reserve v1.1 cases.

#include <test/modelnet_cr11_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace {

std::string TokenFor(modelnet::HcpEngine& e, const std::string& account,
                     const std::vector<std::string>& scopes = {})
{
    const std::string ver = "pkce-verifier-" + account + "-zzzz";
    const std::string ch = e.LabCreatePkceChallenge(ver);
    const std::string code =
        e.LabAuthorize(account, "client-demo", "https://app.example/cb", "state-" + account, ch,
                       scopes.empty() ? cr11_test::Scopes() : scopes);
    UniValue tok;
    std::string err;
    BOOST_REQUIRE(e.LabToken(code, ver, "https://app.example/cb", e.LabJkt(), "", tok, err));
    return tok["access_token"].get_str();
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(modelnet_cr11_priv_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr11_priv_01_reporting_default)
{
    auto e = cr11_test::Lab();
    BOOST_CHECK(e->Cfg().reporting_default_off);
    BOOST_CHECK(!e->ConnectorStatus()["reporting"].isTrue());
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);
    std::string code;
    const UniValue plan = e->PlanLocal(hcp_test::kRecipe, code);
    BOOST_CHECK(code.empty());
    BOOST_CHECK(!plan["inventory_reported"].isTrue());
}

BOOST_AUTO_TEST_CASE(cr11_priv_02_private_response_cache)
{
    auto e = cr11_test::Lab();
    e->PutAccount("account-demo", 1000);
    e->PutAccount("account-b", 777);
    const auto tok_a = cr11_test::Tok(*e);
    const auto tok_b = TokenFor(*e, "account-b");

    auto ra = e->Handle(hcp_test::AuthReq(*e, "GET", "/treasury/balances", tok_a));
    BOOST_REQUIRE_EQUAL(ra.status, 200);
    BOOST_CHECK(ra.CachePrivate());
    BOOST_CHECK_EQUAL(cr11_test::Json(ra)["account_ref"].get_str(), "account-demo");
    BOOST_CHECK_EQUAL(cr11_test::Json(ra)["available_atoms"].get_str(), "1000");

    auto rb = e->Handle(hcp_test::AuthReq(*e, "GET", "/treasury/balances", tok_b));
    BOOST_REQUIRE_EQUAL(rb.status, 200);
    BOOST_CHECK(rb.CachePrivate());
    BOOST_CHECK_EQUAL(cr11_test::Json(rb)["account_ref"].get_str(), "account-b");
    BOOST_CHECK_EQUAL(cr11_test::Json(rb)["available_atoms"].get_str(), "777");

    auto stream = e->Handle(hcp_test::AuthReq(*e, "GET", "/events/stream", tok_a));
    BOOST_REQUIRE_EQUAL(stream.status, 200);
    BOOST_CHECK(stream.CachePrivate());
}

BOOST_AUTO_TEST_CASE(cr11_priv_03_event_partition)
{
    auto e = cr11_test::Lab();
    const auto tok_a = cr11_test::Tok(*e);
    const auto tok_b = TokenFor(*e, "account-b");

    UniValue link_a(UniValue::VOBJ);
    link_a.pushKV("link_id", "evt-demo");
    auto created_a = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/entities/links", tok_a, &link_a));
    BOOST_REQUIRE_EQUAL(created_a.status, 201);

    UniValue link_b(UniValue::VOBJ);
    link_b.pushKV("link_id", "evt-other");
    auto created_b = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/entities/links", tok_b, &link_b));
    BOOST_REQUIRE_EQUAL(created_b.status, 201);

    auto ev_a = e->Handle(hcp_test::AuthReq(*e, "GET", "/events", tok_a));
    BOOST_REQUIRE_EQUAL(ev_a.status, 200);
    BOOST_CHECK(ev_a.body.find("evt-demo") != std::string::npos);
    BOOST_CHECK(ev_a.body.find("evt-other") == std::string::npos);

    auto ev_b = e->Handle(hcp_test::AuthReq(*e, "GET", "/events", tok_b));
    BOOST_REQUIRE_EQUAL(ev_b.status, 200);
    BOOST_CHECK(ev_b.body.find("evt-other") != std::string::npos);
    BOOST_CHECK(ev_b.body.find("evt-demo") == std::string::npos);

    modelnet::HcpHttpRequest cross = hcp_test::AuthReq(*e, "GET", "/events", tok_b);
    cross.query = "account_ref=account-demo";
    auto denied = e->Handle(cross);
    BOOST_CHECK_EQUAL(denied.status, 403);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(denied), "CURSOR_ACCOUNT");

    modelnet::HcpHttpRequest altered = hcp_test::AuthReq(*e, "GET", "/events", tok_a);
    altered.query = "filter=other-entity";
    auto filter = e->Handle(altered);
    BOOST_CHECK_EQUAL(filter.status, 403);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(filter), "CURSOR_FILTER");
}

BOOST_AUTO_TEST_CASE(cr11_priv_04_secret_sentinels)
{
    auto e = cr11_test::Lab();
    const char* sentinel = "CR11_PRIV_SENTINEL_TOKEN";
    e->PutSourceHintWithSecret(std::string("https://evil.example/file?token=") + sentinel);
    e->PutSentinel("tok", sentinel);
    BOOST_CHECK(e->LogRedactionScan()["sentinels_in_export"].isFalse());
    BOOST_CHECK(e->LogRedactionScan()["sentinels_in_logs"].isFalse());
    const UniValue pub = e->ExportPublic(false);
    BOOST_CHECK(pub.write().find(sentinel) == std::string::npos);
    BOOST_CHECK(e->TrafficCapture().write().find(sentinel) == std::string::npos);
    auto tok = cr11_test::Tok(*e);
    auto exp = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/exports", tok));
    BOOST_REQUIRE_EQUAL(exp.status, 201);
    BOOST_CHECK(exp.body.find(sentinel) == std::string::npos);
}

BOOST_AUTO_TEST_CASE(cr11_priv_05_prompt_and_kv)
{
    auto e = cr11_test::Lab();
    e->SetPrivatePrompt("PROMPT_SENTINEL");
    e->SetPrivateKv("KV_SENTINEL");
    const UniValue pub = e->ExportPublic(false);
    BOOST_CHECK(pub["prompt"].isNull());
    BOOST_CHECK(pub["kv"].isNull());
    BOOST_CHECK(pub.write().find("PROMPT_SENTINEL") == std::string::npos);
    BOOST_CHECK(pub.write().find("KV_SENTINEL") == std::string::npos);
    BOOST_CHECK(e->TrafficCapture().write().find("PROMPT_SENTINEL") == std::string::npos);
    BOOST_CHECK(e->ChildRuntimeEnv()["HCP_ACCESS_TOKEN"].isNull());
    auto tok = cr11_test::Tok(*e);
    auto ev = e->Handle(hcp_test::AuthReq(*e, "GET", "/events", tok));
    BOOST_CHECK_EQUAL(ev.status, 200);
    BOOST_CHECK(ev.body.find("PROMPT_SENTINEL") == std::string::npos);
    BOOST_CHECK(ev.body.find("KV_SENTINEL") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(cr11_priv_06_aggregate_analytics)
{
    auto e = cr11_test::Lab();
    e->SetPrivatePrompt("TINY_COHORT_PROMPT");
    const UniValue a = e->AnalyticsView();
    BOOST_CHECK(!a["cross_tenant"].isTrue());
    BOOST_CHECK(a["cohort_suppressed"].isTrue());
    BOOST_CHECK(a.write().find("TINY_COHORT_PROMPT") == std::string::npos);
    BOOST_CHECK(a.write().find("account-demo") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(cr11_priv_07_export_credential_exclusion)
{
    auto e = cr11_test::Lab();
    const auto tok = cr11_test::Tok(*e);
    const UniValue pub = e->ExportPublic(false);
    BOOST_CHECK(pub["include_secrets"].isFalse());
    BOOST_CHECK(!pub.exists("access_token"));
    BOOST_CHECK(!pub.exists("refresh_token"));
    BOOST_CHECK(!pub.exists("client_secret"));
    BOOST_CHECK(!pub.exists("root_sk"));
    BOOST_CHECK(pub["oauth_tokens"].isNull());
    BOOST_CHECK(pub.write().find(tok) == std::string::npos);

    auto exp = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/exports", tok));
    BOOST_REQUIRE_EQUAL(exp.status, 201);
    BOOST_CHECK(cr11_test::Json(exp)["excluded_unauthorized"].isTrue());
    BOOST_CHECK(exp.body.find(tok) == std::string::npos);
    const std::string xid = cr11_test::Json(exp)["export_id"].get_str();
    auto got = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/exports/" + xid, tok));
    BOOST_REQUIRE_EQUAL(got.status, 200);
    BOOST_CHECK(got.body.find(tok) == std::string::npos);
}

BOOST_AUTO_TEST_CASE(cr11_priv_08_adviser_revocation)
{
    auto e = cr11_test::Lab();
    const auto tok = cr11_test::Tok(*e);
    UniValue link(UniValue::VOBJ);
    link.pushKV("link_id", "adviser-priv08");
    link.pushKV("relationship", "ADVISER");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/entities/links", tok, &link));
    BOOST_REQUIRE_EQUAL(r.status, 201);

    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/exports", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK(cr11_test::Json(r)["excluded_unauthorized"].isTrue());
    BOOST_CHECK(r.body.find(tok) == std::string::npos);
    const std::string xid = cr11_test::Json(r)["export_id"].get_str();

    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/entities/links/adviser-priv08/revoke", tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["status"].get_str(), "REVOKED");

    UniValue via(UniValue::VOBJ);
    via.pushKV("via_link", "adviser-priv08");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/portfolios", tok, &via));
    BOOST_CHECK_EQUAL(r.status, 403);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_ENTITY_SCOPE);

    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/exports/" + xid, tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK(cr11_test::Json(r)["excluded_unauthorized"].isTrue());
    BOOST_CHECK(e->Cfg().reporting_default_off);
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);
}

BOOST_AUTO_TEST_CASE(cr11_priv_09_financial_retention_distinction)
{
    auto e = cr11_test::Lab();
    const auto tok = cr11_test::Tok(*e);
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/reports", tok));
    BOOST_REQUIRE_EQUAL(created.status, 201);
    const std::string rid = cr11_test::Json(created)["body"]["report_id"].get_str();
    BOOST_CHECK(!rid.empty());

    e->SetReporting(false);
    BOOST_CHECK(e->Cfg().reporting_default_off);
    BOOST_CHECK(!e->ConnectorStatus()["reporting"].isTrue());
    BOOST_CHECK(!e->AnalyticsView()["cross_tenant"].isTrue());

    auto kept = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/reports/" + rid, tok));
    BOOST_CHECK_EQUAL(kept.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(kept), modelnet::HCP_TYPE_RESERVE_REPORT);
    BOOST_CHECK_EQUAL(cr11_test::Json(kept)["body"]["report_id"].get_str(), rid);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);
}

BOOST_AUTO_TEST_CASE(cr11_priv_10_pairwise_device_identity)
{
    auto a = cr11_test::Lab();
    auto b = cr11_test::Lab();
    b->SwitchProvider("provider-b");
    a->PairDevice("pair-cex-a", "account-demo");
    b->PairDevice("pair-cex-b", "account-demo");

    BOOST_CHECK(a->DevicePaired("pair-cex-a"));
    BOOST_CHECK(!a->DevicePaired("pair-cex-b"));
    BOOST_CHECK(b->DevicePaired("pair-cex-b"));
    BOOST_CHECK(!b->DevicePaired("pair-cex-a"));
    BOOST_CHECK_EQUAL(a->Cfg().provider_id, "provider-demo");
    BOOST_CHECK_EQUAL(b->Cfg().provider_id, "provider-b");
    BOOST_CHECK(a->DualInstancePeerNote()["independent"].isTrue());
    BOOST_CHECK(b->DualInstancePeerNote()["independent"].isTrue());

    const UniValue pub_a = a->ExportPublic(false);
    const UniValue pub_b = b->ExportPublic(false);
    BOOST_CHECK(!pub_a.exists("global_device_id"));
    BOOST_CHECK(!pub_b.exists("tracking_id"));
    BOOST_CHECK(pub_a.write().find("pair-cex-b") == std::string::npos);
    BOOST_CHECK(pub_b.write().find("pair-cex-a") == std::string::npos);

    a->RevokeDevice("pair-cex-a");
    BOOST_CHECK(!a->DevicePaired("pair-cex-a"));
    BOOST_CHECK(b->DevicePaired("pair-cex-b"));
}

BOOST_AUTO_TEST_SUITE_END()
