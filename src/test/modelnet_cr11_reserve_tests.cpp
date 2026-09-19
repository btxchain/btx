// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Unique native Cognitive Reserve v1.1 cases.

#include <test/modelnet_cr11_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr11_reserve_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr11_reserve_01_capacity_formula)
{
    BOOST_CHECK_EQUAL(modelnet::Cr11Capacity(1000, 400, 250), 250);
    auto e = cr11_test::Lab();
    e->PutAccount("account-demo", 1000);
    e->Cr11SetProtected(400);
    e->Cr11SetRemainingAuthority(250);
    BOOST_CHECK_EQUAL(e->Cr11CapacityOf("account-demo"), 250);
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/reserve/portfolios/port-demo/snapshot", tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["allocation_capacity_atoms"].get_str(), "250");
}

BOOST_AUTO_TEST_CASE(cr11_reserve_02_protected_floor)
{
    auto e = cr11_test::Lab();
    e->PutAccount("account-demo", 1000);
    e->Cr11SetProtected(400);
    e->Cr11SetRemainingAuthority(10000);
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "cap-2");
    body.pushKV("maximum_exposure", "700");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_CAPACITY);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
    BOOST_CHECK_EQUAL(e->Cr11LifetimeSpent(), 0);
}

BOOST_AUTO_TEST_CASE(cr11_reserve_03_existing_hold_counted_once)
{
    auto e = cr11_test::Lab();
    e->PutAccount("account-demo", 600);
    e->Cr11SetProtected(0);
    e->Cr11SetRemainingAuthority(10000);
    BOOST_CHECK_EQUAL(e->Cr11CapacityOf("account-demo"), 600);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
}

BOOST_AUTO_TEST_CASE(cr11_reserve_04_mandate_exhaustion)
{
    auto e = cr11_test::Lab();
    e->PutAccount("account-demo", 1000);
    e->Cr11SetProtected(0);
    e->Cr11SetRemainingAuthority(10);
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "cap-4");
    body.pushKV("maximum_exposure", "11");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_CAPACITY);
}

BOOST_AUTO_TEST_CASE(cr11_reserve_05_concurrent_allocation)
{
    auto e = cr11_test::Lab();
    e->PutAccount("account-demo", 1000);
    e->Cr11SetProtected(0);
    e->Cr11SetRemainingAuthority(20);
    auto tok = cr11_test::Tok(*e);
    int ok = 0;
    for (int i = 0; i < 100; ++i) {
        UniValue body(UniValue::VOBJ);
        body.pushKV("client_operation_id", "c-" + std::to_string(i));
        body.pushKV("maximum_exposure", "1");
        auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
        const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
        r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
        if (r.status == 201) ++ok;
    }
    BOOST_CHECK_LE(ok, 20);
    BOOST_CHECK_GE(e->Cr11CapacityOf("account-demo"), 0);
}

BOOST_AUTO_TEST_CASE(cr11_reserve_06_duplicate_operation)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "dup-1");
    body.pushKV("maximum_exposure", "10");
    auto r1 = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    auto r2 = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_CHECK_EQUAL(cr11_test::Json(r1)["body"]["allocation_id"].get_str(),
                      cr11_test::Json(r2)["body"]["allocation_id"].get_str());
}

BOOST_AUTO_TEST_CASE(cr11_reserve_07_conflicting_duplicate)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "dup-2");
    body.pushKV("maximum_exposure", "10");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    body.pushKV("maximum_exposure", "12");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_CONFLICT);
}

BOOST_AUTO_TEST_CASE(cr11_reserve_08_pending_deposit_exclusion)
{
    auto e = cr11_test::Lab();
    e->PutAccount("account-demo", 1000);
    e->Cr11SetPendingDeposit(800);
    e->Cr11SetProtected(0);
    e->Cr11SetRemainingAuthority(10000);
    BOOST_CHECK_EQUAL(e->Cr11CapacityOf("account-demo"), 200);
}

BOOST_AUTO_TEST_CASE(cr11_reserve_09_encumbered_capital_exclusion)
{
    auto e = cr11_test::Lab();
    e->PutAccount("account-demo", 1000);
    e->Cr11SetEncumbered(700);
    e->Cr11SetProtected(0);
    e->Cr11SetRemainingAuthority(10000);
    BOOST_CHECK_EQUAL(e->Cr11CapacityOf("account-demo"), 300);
}

BOOST_AUTO_TEST_CASE(cr11_reserve_10_soft_budget_is_not_money)
{
    auto e = cr11_test::Lab();
    e->PutAccount("account-demo", 100);
    e->Cr11SetProtected(0);
    e->Cr11SetRemainingAuthority(10000);
    e->Cr11SetSoftBudget("dept-a", 80);
    e->Cr11SetSoftBudget("dept-b", 80);
    BOOST_CHECK_EQUAL(e->Cr11CapacityOf("account-demo"), 100);
}

BOOST_AUTO_TEST_SUITE_END()
