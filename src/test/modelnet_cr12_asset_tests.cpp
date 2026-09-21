// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#include <test/modelnet_cr12_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr12_asset_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr12_asset_01)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("label", "Shared Name");
    a.pushKV("namespace", "ns-a");
    a.pushKV("value", "auth-1");
    auto r1 = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets", tok, &a));
    BOOST_CHECK_EQUAL(r1.status, 201);
    UniValue b(UniValue::VOBJ);
    b.pushKV("label", "Shared Name");
    b.pushKV("namespace", "ns-b");
    b.pushKV("value", "auth-2");
    auto r2 = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets", tok, &b));
    BOOST_CHECK_EQUAL(r2.status, 201);
    BOOST_CHECK(cr12_test::Body(r1)["asset_id"].get_str() != cr12_test::Body(r2)["asset_id"].get_str());
    BOOST_CHECK_EQUAL(cr12_test::Body(r1)["label"].get_str(), cr12_test::Body(r2)["label"].get_str());
}

BOOST_AUTO_TEST_CASE(cr12_asset_02)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("namespace", "isin");
    a.pushKV("value", "US0000000001");
    a.pushKV("network", "regtest");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets", tok, &a)).status, 201);
    UniValue b(UniValue::VOBJ);
    b.pushKV("namespace", "isin");
    b.pushKV("value", "US0000000001");
    b.pushKV("network", "regtest");
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets", tok, &b))),
                      modelnet::HCP_ERR_IDENTIFIER_COLLISION);
    auto br = e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/breaks", tok));
    BOOST_CHECK(cr12_test::Body(br)["items"].isArray());
    BOOST_CHECK(cr12_test::Body(br)["items"].size() >= 1);
}

BOOST_AUTO_TEST_CASE(cr12_asset_03)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("value", "reserve-unit");
    a.pushKV("network", "regtest");
    auto r1 = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets", tok, &a));
    UniValue b(UniValue::VOBJ);
    b.pushKV("value", "reserve-unit");
    b.pushKV("network", "signet");
    auto r2 = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets", tok, &b));
    BOOST_CHECK_EQUAL(r1.status, 201);
    BOOST_CHECK_EQUAL(r2.status, 201);
    BOOST_CHECK(cr12_test::Body(r1)["asset_id"].get_str() != cr12_test::Body(r2)["asset_id"].get_str());
    BOOST_CHECK(cr12_test::Body(r1)["network"].get_str() != cr12_test::Body(r2)["network"].get_str());
}

BOOST_AUTO_TEST_CASE(cr12_asset_04)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("kind", "CAPABILITY");
    a.pushKV("label", "public-model");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets", tok, &a));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["asset_kind"].get_str(), "CAPABILITY");
    BOOST_CHECK(cr12_test::Body(r)["ticker"].isNull());
    BOOST_CHECK(cr12_test::Body(r)["security_id"].isNull());
    BOOST_CHECK(cr12_test::Body(r)["synthetic_security"].isFalse());
}

BOOST_AUTO_TEST_CASE(cr12_asset_05)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("kind", "CAPABILITY");
    auto ar = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets", tok, &a));
    const std::string id = cr12_test::Body(ar)["asset_id"].get_str();
    UniValue rights(UniValue::VOBJ);
    rights.pushKV("issuer", "unaccepted-issuer");
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets/" + id + "/rights", tok, &rights))),
                      modelnet::HCP_ERR_ISSUER_UNACCEPTED);
}

BOOST_AUTO_TEST_CASE(cr12_asset_06)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("kind", "CAPABILITY");
    auto ar = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets", tok, &a));
    const std::string id = cr12_test::Body(ar)["asset_id"].get_str();
    UniValue bad(UniValue::VOBJ);
    bad.pushKV("transferability", "NONTRANSFERABLE");
    bad.pushKV("invent_transfer", true);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets/" + id + "/rights", tok, &bad))),
                      modelnet::HCP_ERR_TRANSFER_RESTRICTED);
    UniValue ok(UniValue::VOBJ);
    ok.pushKV("transferability", "NONTRANSFERABLE");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets/" + id + "/rights", tok, &ok)).status, 201);
    UniValue ex(UniValue::VOBJ);
    auto er = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exports", tok, &ex));
    BOOST_CHECK_EQUAL(er.status, 201);
    BOOST_CHECK(cr12_test::Body(er)["transfer_permission"].isFalse());
}

BOOST_AUTO_TEST_CASE(cr12_asset_07)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("kind", "CAPABILITY");
    a.pushKV("public_sponsorship", true);
    a.pushKV("label", "public-release");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets", tok, &a));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK(!cr12_test::Body(r).exists("exclusive_ip"));
    BOOST_CHECK(!cr12_test::Body(r).exists("revenue_entitlement"));
    BOOST_CHECK(cr12_test::Body(r)["synthetic_security"].isFalse());
}

BOOST_AUTO_TEST_CASE(cr12_asset_08)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("kind", "CAPABILITY");
    a.pushKV("label", "parent-company");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets", tok, &a)).status, 201);
    e->Cr11SetFamilyView(true);
    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "sub-debit");
    alloc.pushKV("maximum_exposure", "10");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &alloc));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr12_test::Body(r)["allocation_id"].get_str();
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok))),
                      modelnet::HCP_ERR_FAMILY_VIEW);
}

BOOST_AUTO_TEST_CASE(cr12_asset_09)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("kind", "CAPABILITY");
    auto ar = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets", tok, &a));
    const std::string id = cr12_test::Body(ar)["asset_id"].get_str();
    const std::string created = cr12_test::Body(ar)["created_at"].get_str();
    UniValue rights(UniValue::VOBJ);
    rights.pushKV("expires_at", std::to_string(e->Now() - 1));
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets/" + id + "/rights", tok, &rights)).status, 201);
    auto got = e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/assets/" + id, tok));
    BOOST_CHECK_EQUAL(got.status, 200);
    BOOST_CHECK_EQUAL(cr12_test::Body(got)["asset_id"].get_str(), id);
    BOOST_CHECK_EQUAL(cr12_test::Body(got)["created_at"].get_str(), created);
}

BOOST_AUTO_TEST_CASE(cr12_asset_10)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    const int64_t before = e->Crl12NativeAvailable("account-demo");
    UniValue a(UniValue::VOBJ);
    a.pushKV("label", "institutional");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets", tok, &a)).status, 201);
    BOOST_CHECK_EQUAL(e->Crl12NativeAvailable("account-demo"), before);
    BOOST_CHECK_EQUAL(e->AccountAvailable("account-demo"), before);
}

BOOST_AUTO_TEST_SUITE_END()
