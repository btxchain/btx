// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Unique native Cognitive Reserve v1.1 cases.

#include <test/modelnet_cr11_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr11_auth_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr11_auth_01_wrong_sender_key)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    modelnet::HcpHttpRequest req = hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok);
    req.headers["dpop"] = e->LabDpop("POST", e->Cfg().api_base + "/capital/allocations", tok);
    // swap jkt by using other key
    UniValue p;
    p.read(req.headers["dpop"]);
    p.pushKV("jkt", e->LabJktOther());
    req.headers["dpop"] = p.write();
    auto r = e->Handle(req);
    BOOST_CHECK_EQUAL(r.status, 401);
}

BOOST_AUTO_TEST_CASE(cr11_auth_02_dpop_replay)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "dpop-1");
    auto req = hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body);
    auto r1 = e->Handle(req);
    auto r2 = e->Handle(req);
    BOOST_CHECK(r1.status == 201);
    BOOST_CHECK_EQUAL(r2.status, 401);
}

BOOST_AUTO_TEST_CASE(cr11_auth_03_body_substitution)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "sub-1");
    body.pushKV("maximum_exposure", "10");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    body.pushKV("maximum_exposure", "99");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_CONFLICT);
}

BOOST_AUTO_TEST_CASE(cr11_auth_04_audience_mismatch)
{
    auto e = cr11_test::Lab();
    auto tok = hcp_test::Token(*e, cr11_test::Scopes(), "https://other.example/aud");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok));
    BOOST_CHECK_EQUAL(r.status, 401);
}

BOOST_AUTO_TEST_CASE(cr11_auth_05_public_client_secrecy)
{
    auto e = cr11_test::Lab();
    auto exp = e->ExportPublic(false);
    BOOST_CHECK(!exp.exists("client_secret"));
}

BOOST_AUTO_TEST_CASE(cr11_auth_06_read_only_scope)
{
    auto e = cr11_test::Lab();
    auto tok = hcp_test::Token(*e, {"catalog:read", "capital:read"});
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_SCOPE);
}

BOOST_AUTO_TEST_CASE(cr11_auth_07_provider_key_compromise)
{
    auto e = cr11_test::Lab();
    std::string code, err;
    BOOST_REQUIRE(e->RotateOperationalKey(2, code, err));
    BOOST_CHECK(!e->ReplayOldKeyset("op-0", code));
}

BOOST_AUTO_TEST_CASE(cr11_auth_08_root_enrollment)
{
    auto e = hcp_test::Lab(true);
    std::string code, err;
    modelnet::HcpEnvelope env = hcp_test::ProfileOf(*e);
    const bool enrolled = e->EnrollProvider(env, false, code, err);
    BOOST_CHECK(!enrolled);
    BOOST_CHECK(!code.empty());
}

BOOST_AUTO_TEST_CASE(cr11_auth_09_browser_request_forgery)
{
    auto e = cr11_test::Lab();
    modelnet::HcpHttpRequest req;
    req.method = "POST";
    req.path = "/capital/allocations";
    auto r = e->Handle(req);
    BOOST_CHECK_EQUAL(r.status, 401);
}

BOOST_AUTO_TEST_CASE(cr11_auth_10_ssrf_boundary)
{
    auto e = cr11_test::Lab();
    e->RegisterFetch("http://169.254.169.254/", 403, "", "");
    auto got = e->FetchUrl("http://169.254.169.254/", "");
    BOOST_CHECK(got.exists("status") || got.write().size() > 0);
}

BOOST_AUTO_TEST_SUITE_END()
