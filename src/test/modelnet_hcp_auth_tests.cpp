// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// HCP-AUTH-01 .. HCP-AUTH-08 unique native OAUTH_LAB cases.

#include <test/modelnet_hcp_test.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_hcp_auth_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(hcp_auth_01_authorization_code_pkce)
{
    auto e = hcp_test::Lab();
    const std::string v1 = "verifier-session-one-xxxx";
    const std::string v2 = "verifier-session-two-yyyy";
    const std::string c1 = e->LabAuthorize("account-demo", "c", "https://app.example/cb", "s1",
                                              e->LabCreatePkceChallenge(v1), {"catalog:read"});
    const std::string c2 = e->LabAuthorize("account-b", "c", "https://app.example/cb", "s2",
                                              e->LabCreatePkceChallenge(v2), {"catalog:read"});
    UniValue tok;
    std::string err;
    BOOST_CHECK(!e->LabToken(c1, v2, "https://app.example/cb", e->LabJkt(), "", tok, err));
    BOOST_REQUIRE(e->LabToken(c2, v2, "https://app.example/cb", e->LabJkt(), "", tok, err));
}

BOOST_AUTO_TEST_CASE(hcp_auth_02_sender_constrained_token_theft)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, {"intents:create", "account:read"});
    auto req = hcp_test::AuthReq(*e, "POST", "/finance/intents", tok);
    req.headers["dpop"] = e->LabDpop("POST", e->Cfg().api_base + "/finance/intents", tok);
    // thief jkt
    UniValue p;
    BOOST_REQUIRE(p.read(req.headers["dpop"]));
    p.pushKV("jkt", e->LabJktOther());
    req.headers["dpop"] = p.write();
    auto resp = e->Handle(req);
    BOOST_CHECK_GE(resp.status, 401);
}

BOOST_AUTO_TEST_CASE(hcp_auth_03_audience_enforcement)
{
    auto e = hcp_test::Lab(true);
    const std::string ver = "pkce-verifier-demo-aaaa";
    const std::string code =
        e->LabAuthorize("account-demo", "c", "https://app.example/cb", "s", e->LabCreatePkceChallenge(ver),
                        {"intents:create", "account:read"});
    UniValue tok;
    std::string err;
    BOOST_REQUIRE(e->LabToken(code, ver, "https://app.example/cb", e->LabJkt(), e->Cfg().mcp_audience, tok, err));
    const std::string access = tok["access_token"].get_str();
    auto req = hcp_test::AuthReq(*e, "POST", "/finance/intents", access);
    auto resp = e->Handle(req);
    BOOST_CHECK_GE(resp.status, 401);
}

BOOST_AUTO_TEST_CASE(hcp_auth_04_scope_escalation)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, {"catalog:read"});
    UniValue body(UniValue::VOBJ);
    body.pushKV("action", "FUND_RELEASE");
    auto req = hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body);
    auto resp = e->Handle(req);
    BOOST_CHECK_GE(resp.status, 401);
    auto q = hcp_test::AuthReq(*e, "GET", "/treasury/balances", tok);
    auto r2 = e->Handle(q);
    BOOST_CHECK_GE(r2.status, 401);
}

BOOST_AUTO_TEST_CASE(hcp_auth_05_tenant_object_isolation)
{
    auto e = hcp_test::Lab(true);
    e->PutAccount("account-b", 5000);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    auto req = hcp_test::AuthReq(*e, "GET", "/finance/intents/guess-b", tok);
    auto resp = e->Handle(req);
    BOOST_CHECK(resp.status == 404 || resp.status == 401);
    BOOST_CHECK(resp.body.find("5000") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(hcp_auth_06_dpop_is_not_body_approval)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "op-auth06");
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    BOOST_REQUIRE_EQUAL(created.status, 201);
    UniValue env;
    BOOST_REQUIRE(env.read(created.body));
    const std::string iid = env["body"]["intent_id"].get_str();
    UniValue bad(UniValue::VOBJ);
    bad.pushKV("expected_body_id", std::string(96, '0'));
    auto sub = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/submit", tok, &bad));
    BOOST_CHECK_GE(sub.status, 400);
}

BOOST_AUTO_TEST_CASE(hcp_auth_07_refresh_and_revocation)
{
    auto e = hcp_test::Lab(true);
    const std::string ver = "pkce-verifier-demo-aaaa";
    const std::string code =
        e->LabAuthorize("account-demo", "c", "https://app.example/cb", "s", e->LabCreatePkceChallenge(ver),
                        hcp_test::AllScopes());
    UniValue tok;
    std::string err;
    BOOST_REQUIRE(e->LabToken(code, ver, "https://app.example/cb", e->LabJkt(), "", tok, err));
    e->LabRevokeRefresh(tok["refresh_token"].get_str());
    auto req = hcp_test::AuthReq(*e, "POST", "/finance/intents", tok["access_token"].get_str());
    auto resp = e->Handle(req);
    BOOST_CHECK_GE(resp.status, 401);
}

BOOST_AUTO_TEST_CASE(hcp_auth_08_secret_leakage_sweep)
{
    auto e = hcp_test::Lab();
    e->PutSentinel("oauth", "oauth-sentinel-token");
    e->PutSentinel("aws", "AKIA_SENTINEL");
    auto scan = e->LogRedactionScan();
    BOOST_CHECK(scan["sentinels_in_logs"].isFalse() || !scan["sentinels_in_logs"].isTrue());
    auto child = e->ChildRuntimeEnv();
    BOOST_CHECK(child["HCP_ACCESS_TOKEN"].isNull());
    auto exp = e->ExportPublic(true);
    const std::string dump = exp.write();
    BOOST_CHECK(dump.find("oauth-sentinel-token") == std::string::npos);
    BOOST_CHECK(dump.find("AKIA_SENTINEL") == std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
