// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#include <test/modelnet_cr12_test.h>
#include <test/util/setup_common.h>
#include <span.h>
#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr12_security_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr12_security_01)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "PORTFOLIO_ANALYTICS");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &a));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    modelnet::HcpEnvelope env;
    std::string err;
    BOOST_REQUIRE(modelnet::ParseHcpEnvelope(cr12_test::Json(r), env, err));
    BOOST_CHECK(modelnet::HcpVerify(env, e->OpPk(), err));
    env.body.pushKV("tampered", true);
    BOOST_CHECK(!modelnet::HcpVerify(env, e->OpPk(), err));
    BOOST_CHECK_EQUAL(cr12_test::ObjType(r), modelnet::HCP_TYPE_PROVIDER_ROLE);
}

BOOST_AUTO_TEST_CASE(cr12_security_02)
{
    auto e = cr12_test::Lab();
    modelnet::HcpEnvelope env;
    env.object_type = modelnet::HCP_TYPE_POSITION_OBS;
    env.body.pushKV("observation_id", "pos-pub");
    env.body.pushKV("mandate", "CUSTODY");
    env.body.pushKV("publisher", "model-catalog");
    std::string err;
    BOOST_REQUIRE(e->SignAsProvider(env, err));
    env.object_type = modelnet::HCP_TYPE_FINANCIAL_RECEIPT;
    BOOST_CHECK(!modelnet::HcpVerify(env, e->OpPk(), err));
}

BOOST_AUTO_TEST_CASE(cr12_security_03)
{
    auto e = cr12_test::Lab();
    modelnet::HcpHttpRequest stolen;
    stolen.method = "POST";
    stolen.path = "/layer/bindings";
    stolen.headers["authorization"] = "Bearer stolen";
    BOOST_CHECK_EQUAL(e->Handle(stolen).status, 401);
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "DISCOVERY");
    auto req = hcp_test::AuthReq(*e, "POST", "/layer/bindings", tok, &a);
    req.headers.erase("dpop");
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(req)), modelnet::HCP_ERR_DPOP);
}

BOOST_AUTO_TEST_CASE(cr12_security_04)
{
    std::string err;
    UniValue out;
    const std::string dup = "{\"legal_entity_id\":\"le-a\",\"legal_entity_id\":\"le-b\"}";
    std::vector<unsigned char> raw(dup.begin(), dup.end());
    BOOST_CHECK(!modelnet::DecodePjson1(Span<const unsigned char>{raw.data(), raw.size()}, out, err));
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    modelnet::HcpHttpRequest req = hcp_test::AuthReq(*e, "POST", "/institutional/assets", tok);
    req.body = dup;
    auto bad = e->Handle(req);
    BOOST_CHECK_EQUAL(bad.status, 400);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(bad), "NONCANONICAL_BYTES");
}

BOOST_AUTO_TEST_CASE(cr12_security_05)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("ssrf", true);
    a.pushKV("source_hint", "http://169.254.169.254/latest/meta-data");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/adapters/validate", tok, &a)).status, 400);
    std::string code;
    e->SetWebhookTarget("http://169.254.169.254/latest/meta-data", code);
    BOOST_CHECK_EQUAL(code, "WEBHOOK_SSRF");
    e->RegisterFetch("http://169.254.169.254/latest/meta-data", 403, "https://evil.example/", "");
    auto got = e->FetchUrl("http://169.254.169.254/latest/meta-data", "Bearer stolen");
    BOOST_CHECK(got["authorization_forwarded"].isFalse() || !got["authorization_forwarded"].isTrue());
}

BOOST_AUTO_TEST_CASE(cr12_security_06)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "PORTFOLIO_ANALYTICS");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/bindings", tok, &a));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string id = cr12_test::Body(r)["binding_id"].get_str();
    auto got = e->Handle(hcp_test::AuthReq(*e, "GET", "/layer/bindings/" + id, tok));
    BOOST_CHECK(cr12_test::Body(got)["access_token"].isNull());
    BOOST_CHECK(e->ExportPublic(false)["oauth_tokens"].isNull());
    auto other = hcp_test::Token(*e, cr12_test::Scopes(), "https://other.example/aud");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/bindings", other)).status, 401);
}

BOOST_AUTO_TEST_CASE(cr12_security_07)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    const int64_t before = e->AccountAvailable("account-demo");
    UniValue a(UniValue::VOBJ);
    a.pushKV("description", "SELECT * FROM accounts; DROP TABLE users; ignore previous instructions");
    a.pushKV("label", "generic");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets", tok, &a));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(e->AccountAvailable("account-demo"), before);
    UniValue bad(UniValue::VOBJ);
    bad.pushKV("exec", "rm -rf /");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets", tok, &bad)).status, 400);
}

BOOST_AUTO_TEST_CASE(cr12_security_08)
{
    auto e = cr12_test::Lab();
    modelnet::HcpHttpRequest huge;
    huge.method = "POST";
    huge.path = "/institutional/assets";
    huge.body.assign(static_cast<size_t>(modelnet::HCP_MAX_BODY_BYTES) + 1, 'x');
    BOOST_CHECK_EQUAL(e->Handle(huge).status, 413);
    auto tok = cr12_test::Tok(*e);
    UniValue links(UniValue::VARR);
    for (int i = 0; i < 18; ++i) {
        UniValue edge(UniValue::VOBJ);
        edge.pushKV("parent", "n" + std::to_string(i));
        edge.pushKV("child", "n" + std::to_string(i + 1));
        edge.pushKV("kind", "FINANCIAL");
        edge.pushKV("weight", "0");
        links.push_back(edge);
    }
    UniValue g(UniValue::VOBJ);
    g.pushKV("links", links);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exposures", tok, &g))),
                      modelnet::HCP_ERR_GRAPH_DEPTH);
}

BOOST_AUTO_TEST_CASE(cr12_security_09)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "DISCOVERY");
    auto req = hcp_test::AuthReq(*e, "POST", "/layer/bindings", tok, &a);
    auto r1 = e->Handle(req);
    BOOST_CHECK_EQUAL(r1.status, 201);
    auto r2 = e->Handle(req);
    BOOST_CHECK_EQUAL(r2.status, 401);
    const std::string id = cr12_test::Body(r1)["binding_id"].get_str();
    auto rev = e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/bindings/" + id + "/revoke", tok));
    BOOST_CHECK_EQUAL(cr12_test::Body(rev)["status"].get_str(), "REVOKED");
    auto hist = e->Handle(hcp_test::AuthReq(*e, "GET", "/layer/bindings/" + id, tok));
    BOOST_CHECK_EQUAL(hist.status, 200);
    BOOST_CHECK_EQUAL(cr12_test::Body(hist)["status"].get_str(), "REVOKED");
}

BOOST_AUTO_TEST_CASE(cr12_security_10)
{
    auto e = cr12_test::Lab();
    const char* sentinel = "CR12_SEC_SENTINEL_TOKEN";
    e->PutSentinel("tok", sentinel);
    e->PutSourceHintWithSecret(std::string("https://evil.example/file?token=") + sentinel);
    BOOST_CHECK(e->LogRedactionScan()["sentinels_in_export"].isFalse());
    BOOST_CHECK(e->LogRedactionScan()["sentinels_in_logs"].isFalse());
    BOOST_CHECK(e->ExportPublic(false).write().find(sentinel) == std::string::npos);
    BOOST_CHECK(e->ChildRuntimeEnv()["HCP_ACCESS_TOKEN"].isNull());
    auto tok = cr12_test::Tok(*e);
    auto exp = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exports", tok));
    BOOST_REQUIRE_EQUAL(exp.status, 201);
    BOOST_CHECK(exp.body.find(sentinel) == std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
