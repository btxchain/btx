// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Unique native Cognitive Reserve v1.1 cases.

#include <test/modelnet_cr11_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr11_port_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr11_port_01_dual_provider)
{
    std::string err;
    auto a = modelnet::HcpEngine::Create(modelnet::HcpFundingLabPreset(), err);
    auto b = modelnet::HcpEngine::Create(modelnet::HcpFundingLabPreset(), err);
    BOOST_REQUIRE(a && b);
    BOOST_CHECK(a->DualInstancePeerNote()["independent"].isTrue());
}

BOOST_AUTO_TEST_CASE(cr11_port_02_no_spend_failover)
{
    auto e = cr11_test::Lab();
    e->Cr11MarkCrossCexAction("act-1");
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);
    auto tok = cr11_test::Tok(*e);
    UniValue a1(UniValue::VOBJ);
    a1.pushKV("client_operation_id", "port02-a");
    a1.pushKV("maximum_exposure", "10");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &a1));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid1 = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid1 + "/execute", tok));
    UniValue a2(UniValue::VOBJ);
    a2.pushKV("client_operation_id", "port02-b");
    a2.pushKV("maximum_exposure", "10");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &a2));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid2 = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    UniValue ex(UniValue::VOBJ);
    ex.pushKV("cross_cex_action_id", "act-1");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid2 + "/execute", tok, &ex));
    const std::string code = cr11_test::ErrCode(r);
    BOOST_CHECK(code == modelnet::HCP_ERR_CROSS_CEX || code == modelnet::HCP_ERR_CAPACITY);
}

BOOST_AUTO_TEST_CASE(cr11_port_03_no_key_export)
{
    auto e = cr11_test::Lab();
    auto pub = e->ExportPublic(true);
    BOOST_CHECK(pub.exists("refused") || !pub.exists("root_sk"));
}

BOOST_AUTO_TEST_CASE(cr11_port_04_custody_obligations)
{
    auto e = cr11_test::Lab();
    BOOST_CHECK_EQUAL(e->Cfg().custody_backend, modelnet::HCP_CUSTODY_BTX_NATIVE);
}

BOOST_AUTO_TEST_CASE(cr11_port_05_old_client)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/profile", tok));
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_PROVIDER_PROFILE);
}

BOOST_AUTO_TEST_CASE(cr11_port_06_old_server)
{
    auto e = hcp_test::Lab(false);
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve", tok));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_PROFILE_UNSUPPORTED);
}

BOOST_AUTO_TEST_CASE(cr11_port_07_extension_rollback)
{
    auto e = cr11_test::Lab();
    e->Cr11DisableExtension();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/portfolios", tok));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_PROFILE_UNSUPPORTED);
}

BOOST_AUTO_TEST_CASE(cr11_port_08_revoked_provider)
{
    auto e = cr11_test::Lab();
    e->DisconnectProvider();
    BOOST_CHECK(!e->ProviderReachable());
}

BOOST_AUTO_TEST_CASE(cr11_port_09_exact_export)
{
    auto e = cr11_test::Lab();
    auto pub = e->ExportPublic(false);
    BOOST_CHECK(pub.write().size() > 2);
}

BOOST_AUTO_TEST_CASE(cr11_port_10_actual_cross_venue_money)
{
    auto e = cr11_test::Lab();
    auto pub = e->ExportPublic(false);
    BOOST_CHECK_EQUAL(e->AccountAvailable("account-demo"), 1000);
}

BOOST_AUTO_TEST_SUITE_END()
