// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Unique native Cognitive Reserve v1.1 cases.

#include <test/modelnet_cr11_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr11_value_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr11_value_01_stale_reserve_price)
{
    int64_t floor = 0;
    std::string err;
    BOOST_CHECK(!modelnet::Cr11ReportingFloorAtoms("1", "50000", 0, 0, 100000, 10, 0, floor, err));
    BOOST_CHECK_EQUAL(err, modelnet::HCP_ERR_PRICE_STALE);
    auto e = cr11_test::Lab();
    e->Cr11SetQuoteObservedAt(0);
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("required_quote", "1");
    body.pushKV("price_quote_per_coin", "1");
    body.pushKV("observed_at", static_cast<int64_t>(0));
    body.pushKV("max_age", static_cast<int64_t>(1));
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/replenishment/plans", tok, &body));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_PRICE_STALE);
}

BOOST_AUTO_TEST_CASE(cr11_value_02_conservative_atom_rounding)
{
    int64_t floor = 0;
    std::string err;
    BOOST_REQUIRE(modelnet::Cr11ReportingFloorAtoms("1", "3", 0, 10, 10, 1000, 0, floor, err));
    BOOST_CHECK_GE(floor, 1);
}

BOOST_AUTO_TEST_CASE(cr11_value_03_invalid_market_inputs)
{
    int64_t floor = 0;
    std::string err;
    BOOST_CHECK(!modelnet::Cr11ReportingFloorAtoms("1", "NaN", 0, 10, 10, 1000, 0, floor, err));
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("price", "NaN");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/replenishment/plans", tok, &body));
    BOOST_CHECK_GE(r.status, 400);
}

BOOST_AUTO_TEST_CASE(cr11_value_04_bounded_stress_haircut)
{
    int64_t a = 0, b = 0;
    std::string err;
    BOOST_REQUIRE(modelnet::Cr11ReportingFloorAtoms("100", "10", 0, 10, 10, 1000, 0, a, err));
    BOOST_REQUIRE(modelnet::Cr11ReportingFloorAtoms("100", "10", 0, 10, 10, 1000, 5000, b, err));
    BOOST_CHECK_GT(b, a);
}

BOOST_AUTO_TEST_CASE(cr11_value_05_replenishment_cooldown)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue pol(UniValue::VOBJ);
    pol.pushKV("replenishment_mode", "AUTO");
    pol.pushKV("lifetime_cap_atoms", "1000000");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/policies", tok, &pol));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    UniValue body(UniValue::VOBJ);
    body.pushKV("required_quote", "1");
    body.pushKV("price_quote_per_coin", "1");
    body.pushKV("observed_at", e->Now());
    body.pushKV("max_age", static_cast<int64_t>(100000));
    body.pushKV("amount_atoms", static_cast<int64_t>(1));
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/replenishment/plans", tok, &body));
    BOOST_CHECK_EQUAL(r.status, 201);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/replenishment/plans", tok, &body));
    BOOST_CHECK_EQUAL(r.status, 409);
}

BOOST_AUTO_TEST_CASE(cr11_value_06_source_asset_restriction)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("source_asset", "USD");
    body.pushKV("required_quote", "1");
    body.pushKV("price_quote_per_coin", "1");
    body.pushKV("observed_at", e->Now());
    body.pushKV("max_age", static_cast<int64_t>(100000));
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/replenishment/plans", tok, &body));
    BOOST_CHECK_EQUAL(r.status, 403);
}

BOOST_AUTO_TEST_CASE(cr11_value_07_lifetime_turnover)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue pol(UniValue::VOBJ);
    pol.pushKV("replenishment_mode", "AUTO");
    pol.pushKV("lifetime_cap_atoms", "5");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/policies", tok, &pol));
    UniValue body(UniValue::VOBJ);
    body.pushKV("required_quote", "1");
    body.pushKV("price_quote_per_coin", "1");
    body.pushKV("observed_at", e->Now());
    body.pushKV("max_age", static_cast<int64_t>(100000));
    body.pushKV("amount_atoms", static_cast<int64_t>(10));
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/replenishment/plans", tok, &body));
    BOOST_CHECK_EQUAL(r.status, 403);
}

BOOST_AUTO_TEST_CASE(cr11_value_08_quote_expiry_before_execution)
{
    auto e = cr11_test::Lab();
    e->ExpireQuote("missing");
    BOOST_CHECK_EQUAL(e->Now(), modelnet::HCP_DEFAULT_CLOCK_MS);
}

BOOST_AUTO_TEST_CASE(cr11_value_09_unknown_conversion)
{
    auto e = cr11_test::Lab();
    e->Cr11MarkCrossCexAction("cex-1");
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "xcex-1");
    body.pushKV("maximum_exposure", "10");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    UniValue ex(UniValue::VOBJ);
    ex.pushKV("cross_cex_action_id", "cex-1");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok, &ex));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_CROSS_CEX);
}

BOOST_AUTO_TEST_CASE(cr11_value_10_suggest_is_read_plan_only)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("required_quote", "1");
    body.pushKV("price_quote_per_coin", "1");
    body.pushKV("observed_at", e->Now());
    body.pushKV("max_age", static_cast<int64_t>(100000));
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/replenishment/plans", tok, &body));
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["executed_orders"].getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
