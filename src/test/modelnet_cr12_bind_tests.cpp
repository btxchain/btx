// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#include <test/modelnet_cr12_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr12_bind_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr12_bind_01)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "PORTFOLIO_ANALYTICS");
    a.pushKV("secret_ref", "os:keyring/x");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/bindings", tok, &a)).status, 201);
}

BOOST_AUTO_TEST_CASE(cr12_bind_02)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "UNKNOWN");
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/bindings", tok, &a))),
                      modelnet::HCP_ERR_ROLE_UNAVAILABLE);
}

BOOST_AUTO_TEST_CASE(cr12_bind_03)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("access_token", "stolen");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/bindings", tok, &a)).status, 400);
}

BOOST_AUTO_TEST_CASE(cr12_bind_04)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "DISCOVERY");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/bindings", tok, &a));
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/bindings/" + cr12_test::Body(r)["binding_id"].get_str() + "/revoke", tok));
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["status"].get_str(), "REVOKED");
}

BOOST_AUTO_TEST_CASE(cr12_bind_05)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "DISCOVERY");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/bindings", tok, &a));
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/layer/bindings/" + cr12_test::Body(r)["binding_id"].get_str(), tok));
    BOOST_CHECK(cr12_test::Body(r)["access_token"].isNull());
}

BOOST_AUTO_TEST_CASE(cr12_bind_06)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/layer/bindings", tok)).status, 200);
}

BOOST_AUTO_TEST_CASE(cr12_bind_07)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("ssrf", true);
    a.pushKV("source_hint", "http://169.254.169.254/latest/meta-data");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/adapters/validate", tok, &a)).status, 400);
}

BOOST_AUTO_TEST_CASE(cr12_bind_08)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("disabled", true);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/adapters/validate", tok, &a))),
                      modelnet::HCP_ERR_ADAPTER_DISABLED);
}

BOOST_AUTO_TEST_CASE(cr12_bind_09)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("binding_id", "bind-same");
    a.pushKV("role", "DISCOVERY");
    e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/bindings", tok, &a));
    auto r2 = e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/bindings", tok, &a));
    BOOST_CHECK(cr12_test::Body(r2)["generation"].getInt<int64_t>() >= 1);
}

BOOST_AUTO_TEST_CASE(cr12_bind_10)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("secret_ref", "os:keyring/binding");
    BOOST_CHECK(cr12_test::Body(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/bindings", tok, &a)))["secret_ref"]
                    .get_str()
                    .find("os:") == 0);
}

BOOST_AUTO_TEST_CASE(cr12_bind_11_network_mismatch)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    for (const char* net : {"mainnet", "bitcoin"}) {
        UniValue a(UniValue::VOBJ);
        a.pushKV("role", "DISCOVERY");
        a.pushKV("network", net);
        BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/bindings", tok, &a))),
                          modelnet::HCP_ERR_NETWORK_MISMATCH);
    }
}

BOOST_AUTO_TEST_CASE(cr12_bind_12_revoked_status_stays)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "DISCOVERY");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/bindings", tok, &a));
    const std::string id = cr12_test::Body(r)["binding_id"].get_str();
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/bindings/" + id + "/revoke", tok)).status, 200);
    auto rec = cr12_test::Tok(*e, {"bindings:read", "reconciliation:read"});
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/layer/bindings/" + id, rec));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["status"].get_str(), "REVOKED");
}

BOOST_AUTO_TEST_CASE(cr12_bind_13_consent_activates)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "DISCOVERY");
    a.pushKV("owner_consent", true);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/bindings", tok, &a));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["status"].get_str(), "ACTIVE");
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["lifecycle"].get_str(), "CONSENTED");
}

BOOST_AUTO_TEST_SUITE_END()
