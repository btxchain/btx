// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#include <test/modelnet_cr12_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr12_role_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr12_role_01)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    for (const char* role : {"DISCOVERY", "CUSTODY", "EXECUTION", "FUNDING", "TREASURY", "DEVICE_HANDOFF",
                             "ASSET_SERVICING", "PORTFOLIO_ANALYTICS", "FIAT_RAIL"}) {
        UniValue a(UniValue::VOBJ);
        a.pushKV("role", role);
        BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &a)).status, 201);
    }
}

BOOST_AUTO_TEST_CASE(cr12_role_02)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "PORTFOLIO_ANALYTICS");
    a.pushKV("claimed_effect", "CUSTODY");
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &a))),
                      modelnet::HCP_ERR_ROLE_EFFECT);
}

BOOST_AUTO_TEST_CASE(cr12_role_03)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "FIAT_RAIL");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &a));
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/layer/roles/" + cr12_test::Body(r)["manifest_id"].get_str(), tok));
    BOOST_CHECK_EQUAL(r.status, 200);
}

BOOST_AUTO_TEST_CASE(cr12_role_04)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    BOOST_CHECK(cr12_test::Json(e->Handle(hcp_test::AuthReq(*e, "GET", "/layer/roles", tok)))["items"].isArray());
}

BOOST_AUTO_TEST_CASE(cr12_role_05)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "TREASURY");
    BOOST_CHECK_EQUAL(cr12_test::ObjType(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &a))),
                      modelnet::HCP_TYPE_PROVIDER_ROLE);
}

BOOST_AUTO_TEST_CASE(cr12_role_06)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/layer/roles/missing", tok)).status, 404);
}

BOOST_AUTO_TEST_CASE(cr12_role_07)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "DEVICE_HANDOFF");
    e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &a));
    BOOST_CHECK_EQUAL(e->AccountAvailable("account-demo"), e->Crl12NativeAvailable("account-demo"));
}

BOOST_AUTO_TEST_CASE(cr12_role_08)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "EXECUTION");
    BOOST_CHECK_EQUAL(cr12_test::Body(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &a)))["schema_revision"]
                          .get_str(),
                      "1.2");
}

BOOST_AUTO_TEST_CASE(cr12_role_09)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "ASSET_SERVICING");
    a.pushKV("manifest_id", "role-gen");
    e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &a));
    auto r2 = e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &a));
    BOOST_CHECK(cr12_test::Body(r2)["generation"].getInt<int64_t>() >= 1);
}

BOOST_AUTO_TEST_CASE(cr12_role_10)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e, {"catalog:read"});
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "DISCOVERY");
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &a))),
                      modelnet::HCP_ERR_SCOPE);
}

BOOST_AUTO_TEST_SUITE_END()
