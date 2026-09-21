// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#include <test/modelnet_cr12_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr12_neutral_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr12_neutral_01)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "DISCOVERY");
    a.pushKV("manifest_id", "role-provider-a");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &a)).status, 201);
    UniValue b(UniValue::VOBJ);
    b.pushKV("role", "DISCOVERY");
    b.pushKV("manifest_id", "role-provider-b");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &b)).status, 201);
}

BOOST_AUTO_TEST_CASE(cr12_neutral_02)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "PORTFOLIO_ANALYTICS");
    a.pushKV("brand", "Goldman Sachs");
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &a))),
                      modelnet::HCP_ERR_BRAND_DISPATCH);
}

BOOST_AUTO_TEST_CASE(cr12_neutral_03)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "PORTFOLIO_ANALYTICS");
    a.pushKV("claimed_effect", "FUNDING");
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &a))),
                      modelnet::HCP_ERR_ROLE_EFFECT);
}

BOOST_AUTO_TEST_CASE(cr12_neutral_04)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "NOT_A_ROLE");
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &a))),
                      modelnet::HCP_ERR_ROLE_UNAVAILABLE);
}

BOOST_AUTO_TEST_CASE(cr12_neutral_05)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "DISCOVERY");
    a.pushKV("unregistered_endpoint", true);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &a))),
                      modelnet::HCP_ERR_ROLE_EFFECT);
}

BOOST_AUTO_TEST_CASE(cr12_neutral_06)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve/v1.2", tok));
    BOOST_CHECK(cr12_test::Body(r)["not_inferred_from_provider_name"].isTrue());
}

BOOST_AUTO_TEST_CASE(cr12_neutral_07)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "DISCOVERY");
    a.pushKV("comment", "research citation");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &a)).status, 201);
}

BOOST_AUTO_TEST_CASE(cr12_neutral_08)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "PORTFOLIO_ANALYTICS");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &a));
    BOOST_CHECK(!cr12_test::Body(r).exists("invented_aum"));
}

BOOST_AUTO_TEST_CASE(cr12_neutral_09)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "DISCOVERY");
    a.pushKV("package_core_version", 4);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &a))),
                      modelnet::HCP_ERR_CORE_V4);
}

BOOST_AUTO_TEST_CASE(cr12_neutral_10)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "DISCOVERY");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &a)).status, 201);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &a)).status, 201);
}

BOOST_AUTO_TEST_SUITE_END()
