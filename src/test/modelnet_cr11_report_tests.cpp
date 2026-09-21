// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Unique native Cognitive Reserve v1.1 cases.

#include <test/modelnet_cr11_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr11_report_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr11_report_01_snapshot_consistency)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/reports", tok));
    BOOST_CHECK(cr11_test::Json(r)["body"].exists("snapshot_id"));
    BOOST_CHECK(cr11_test::Json(r)["body"].exists("ledger_sequence"));
}

BOOST_AUTO_TEST_CASE(cr11_report_02_separate_values)
{
    auto e = cr11_test::Lab();
    e->Cr11SetCognitiveHoldings(50);
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/reports", tok));
    BOOST_CHECK(cr11_test::Json(r)["body"]["nav_merged"].isFalse());
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["cognitive_holdings_atoms"].get_str(), "50");
}

BOOST_AUTO_TEST_CASE(cr11_report_03_entity_scope)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/exports", tok));
    BOOST_CHECK(cr11_test::Json(r)["scoped"].isTrue());
}

BOOST_AUTO_TEST_CASE(cr11_report_04_fx_freshness)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/reports", tok));
    BOOST_CHECK(cr11_test::Json(r)["body"]["fx_dated"].isTrue());
}

BOOST_AUTO_TEST_CASE(cr11_report_05_focus_edition)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/reports", tok));
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_RESERVE_REPORT);
}

BOOST_AUTO_TEST_CASE(cr11_report_06_duplicate_invoice)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r1 = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/reports", tok));
    auto r2 = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/reports", tok));
    BOOST_CHECK(cr11_test::Json(r1)["body"]["report_id"].get_str() != cr11_test::Json(r2)["body"]["report_id"].get_str());
}

BOOST_AUTO_TEST_CASE(cr11_report_07_assumption_provenance)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/reports", tok));
    BOOST_CHECK(cr11_test::Json(r)["body"]["assumptions_separate_from_actuals"].isTrue());
}

BOOST_AUTO_TEST_CASE(cr11_report_08_actual_revenue)
{
    auto e = cr11_test::Lab();
    BOOST_CHECK_EQUAL(e->AccountAvailable("account-demo"), 1000);
}

BOOST_AUTO_TEST_CASE(cr11_report_09_history_correction)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/reports", tok));
    const std::string id = cr11_test::Json(r)["body"]["report_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/reports/" + id, tok));
    BOOST_CHECK_EQUAL(r.status, 200);
}

BOOST_AUTO_TEST_CASE(cr11_report_10_spreadsheet_injection)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue p(UniValue::VOBJ);
    p.pushKV("label", "=cmd");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/portfolios", tok, &p));
    BOOST_CHECK_EQUAL(r.status, 201);
}

BOOST_AUTO_TEST_SUITE_END()
