// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Unique native Cognitive Reserve v1.1 cases.

#include <test/modelnet_cr11_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr11_hold_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr11_hold_01_public_free_holding)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/positions", tok));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK(!cr11_test::Json(r)["body"].exists("acquisition_price"));
}

BOOST_AUTO_TEST_CASE(cr11_hold_02_exact_recipe_identity)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("recipe_id", std::string(96, '3'));
    a.pushKV("position_id", "p1");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/positions", tok, &a));
    UniValue b(UniValue::VOBJ);
    b.pushKV("recipe_id", std::string(96, '4'));
    b.pushKV("position_id", "p2");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/positions", tok, &b));
    BOOST_CHECK(cr11_test::Json(r)["body"]["recipe_id"].get_str() != std::string(96, '3'));
}

BOOST_AUTO_TEST_CASE(cr11_hold_03_rights_independence)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/positions", tok));
    BOOST_CHECK(cr11_test::Json(r)["body"].exists("rights_ref"));
}

BOOST_AUTO_TEST_CASE(cr11_hold_04_shared_base_allocation)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/positions", tok));
    BOOST_CHECK(cr11_test::Json(r)["nav_merged"].isFalse());
}

BOOST_AUTO_TEST_CASE(cr11_hold_05_ready_is_local_evidence)
{
    auto e = cr11_test::Lab();
    e->SetReadiness("device-demo", "NOT_READY");
    const UniValue job = e->LastHandoffJob();
    if (job.exists("readiness")) {
        BOOST_CHECK(job["readiness"].get_str() != "RUNTIME_READY");
    } else {
        BOOST_CHECK(job.write().find("RUNTIME_READY") == std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(cr11_hold_06_lock_update)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("lock_id", "lock-old");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/positions", tok, &a));
    const std::string id = cr11_test::Json(r)["body"]["position_id"].get_str();
    UniValue u(UniValue::VOBJ);
    u.pushKV("lifecycle", "LOCKED");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/positions/" + id + "/lifecycle", tok, &u));
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["generation"].get_str(), "2");
}

BOOST_AUTO_TEST_CASE(cr11_hold_07_retirement_is_not_deletion)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/positions", tok));
    const std::string id = cr11_test::Json(r)["body"]["position_id"].get_str();
    UniValue u(UniValue::VOBJ);
    u.pushKV("lifecycle", "RETIRED");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/positions/" + id + "/lifecycle", tok, &u));
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/positions/" + id, tok));
    BOOST_CHECK_EQUAL(r.status, 200);
}

BOOST_AUTO_TEST_CASE(cr11_hold_08_provider_exit)
{
    auto e = cr11_test::Lab();
    e->DisconnectProvider();
    BOOST_CHECK(!e->ProviderReachable());
}

BOOST_AUTO_TEST_CASE(cr11_hold_09_cost_not_liquid_mark)
{
    auto e = cr11_test::Lab();
    e->Cr11SetCognitiveHoldings(999999);
    e->PutAccount("account-demo", 1000);
    BOOST_CHECK_EQUAL(e->Cr11CapacityOf("account-demo"), modelnet::Cr11Capacity(1000, 400, 250));
}

BOOST_AUTO_TEST_CASE(cr11_hold_10_private_inventory)
{
    auto e = cr11_test::Lab();
    e->SetReporting(false);
    auto pub = e->ExportPublic(false);
    BOOST_CHECK(!pub.exists("private_inventory"));
}

BOOST_AUTO_TEST_SUITE_END()
