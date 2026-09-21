// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#include <test/modelnet_cr12_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr12_negotiate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr12_negotiate_01)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve/v1.2", tok));
    BOOST_CHECK_EQUAL(cr12_test::ObjType(r), modelnet::HCP_TYPE_LAYER_EXTENSION);
}

BOOST_AUTO_TEST_CASE(cr12_negotiate_02)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    auto r11 = e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve", tok));
    auto r12 = e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve/v1.2", tok));
    BOOST_CHECK_EQUAL(r11.status, 200);
    BOOST_CHECK_EQUAL(r12.status, 200);
    BOOST_CHECK(cr12_test::ObjType(r11) != cr12_test::ObjType(r12));
}

BOOST_AUTO_TEST_CASE(cr12_negotiate_03)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/health", tok));
    BOOST_CHECK(cr12_test::Json(r)["cognitive_reserve"].isTrue());
    BOOST_CHECK(cr12_test::Json(r)["cognitive_reserve_layer"].isTrue());
}

BOOST_AUTO_TEST_CASE(cr12_negotiate_04)
{
    auto e = cr12_test::Lab();
    e->Crl12SetEnabled(false);
    auto tok = cr12_test::Tok(*e);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve/v1.2", tok))),
                      modelnet::HCP_ERR_PROFILE_UNSUPPORTED);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve", tok)).status, 200);
}

BOOST_AUTO_TEST_CASE(cr12_negotiate_05)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    BOOST_CHECK_EQUAL(cr12_test::ObjType(e->Handle(hcp_test::AuthReq(*e, "GET", "/profile", tok))),
                      modelnet::HCP_TYPE_PROVIDER_PROFILE);
}

BOOST_AUTO_TEST_CASE(cr12_negotiate_06)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("objective", "own-then-run");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/plans", tok, &body)).status, 201);
}

BOOST_AUTO_TEST_CASE(cr12_negotiate_07)
{
    BOOST_CHECK(modelnet::HcpObjectTypeOk(modelnet::HCP_TYPE_LAYER_EXTENSION));
    BOOST_CHECK(modelnet::HcpObjectTypeOk(modelnet::HCP_TYPE_RESERVE_EXTENSION));
}

BOOST_AUTO_TEST_CASE(cr12_negotiate_08)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "DISCOVERY");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &a)).status, 201);
}

BOOST_AUTO_TEST_CASE(cr12_negotiate_09)
{
    BOOST_CHECK(modelnet::HcpDomain(modelnet::HCP_TYPE_LAYER_EXTENSION).find("LayerExtensionProfileV1_2") !=
                std::string::npos);
}

BOOST_AUTO_TEST_CASE(cr12_negotiate_10)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/layer/conformance/self-1", tok));
    BOOST_CHECK(cr12_test::Body(r)["not_central_certification"].isTrue());
}

BOOST_AUTO_TEST_SUITE_END()
