// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Unique native Cognitive Reserve v1.1 cases.

#include <test/modelnet_cr11_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr11_tco_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr11_tco_01_worked_ownership_case)
{
    UniValue out;
    std::string err;
    BOOST_REQUIRE(modelnet::Cr11Tco("20000000", "0.01", 3, "50000", "65000", true, true, out, err));
    BOOST_CHECK_EQUAL(out["external"].get_str(), "600000");
    BOOST_CHECK_EQUAL(out["local"].get_str(), "245000");
}

BOOST_AUTO_TEST_CASE(cr11_tco_02_quality_equivalence)
{
    UniValue out;
    std::string err;
    BOOST_CHECK(!modelnet::Cr11Tco("20000000", "0.01", 3, "50000", "65000", false, true, out, err));
    BOOST_CHECK_EQUAL(err, modelnet::HCP_ERR_QUALITY);
}

BOOST_AUTO_TEST_CASE(cr11_tco_03_unknown_cost)
{
    UniValue out;
    std::string err;
    BOOST_CHECK(!modelnet::Cr11Tco("20000000", "0.01", 3, "50000", "65000", true, false, out, err));
    BOOST_CHECK_EQUAL(err, modelnet::HCP_ERR_INPUT_UNKNOWN);
}

BOOST_AUTO_TEST_CASE(cr11_tco_04_unit_separation)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("unit_mismatch", true);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/comparisons", tok, &body));
    BOOST_CHECK_EQUAL(r.status, 400);
}

BOOST_AUTO_TEST_CASE(cr11_tco_05_hardware_counted_once)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/comparisons", tok));
    BOOST_CHECK(cr11_test::Json(r)["body"]["hardware_counted_once"].isTrue());
}

BOOST_AUTO_TEST_CASE(cr11_tco_06_utilization_sensitivity)
{
    UniValue a, b;
    std::string err;
    BOOST_REQUIRE(modelnet::Cr11Tco("1000000", "0.01", 3, "50000", "65000", true, true, a, err));
    BOOST_REQUIRE(modelnet::Cr11Tco("20000000", "0.01", 3, "50000", "65000", true, true, b, err));
    BOOST_CHECK(a["external"].get_str() != b["external"].get_str());
}

BOOST_AUTO_TEST_CASE(cr11_tco_07_horizon_boundaries)
{
    UniValue out;
    std::string err;
    BOOST_CHECK(!modelnet::Cr11Tco("1", "0.01", 0, "1", "1", true, true, out, err));
    BOOST_CHECK_EQUAL(err, modelnet::HCP_ERR_HORIZON);
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("horizon_months", 0);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/workloads", tok, &body));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_HORIZON);
}

BOOST_AUTO_TEST_CASE(cr11_tco_08_forecast_versus_actual)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("forecast_as_actual", true);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/plans", tok, &body));
    BOOST_CHECK_EQUAL(r.status, 400);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/reports", tok));
    BOOST_CHECK(cr11_test::Json(r)["body"]["assumptions_separate_from_actuals"].isTrue());
}

BOOST_AUTO_TEST_CASE(cr11_tco_09_private_workload_inputs)
{
    auto e = cr11_test::Lab();
    e->SetPrivatePrompt("SECRET_PROMPT");
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("prompt", "do not send");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/comparisons", tok, &body));
    BOOST_CHECK_EQUAL(r.status, 400);
    BOOST_CHECK(e->LogRedactionScan()["child_env_clean"].isTrue());
}

BOOST_AUTO_TEST_CASE(cr11_tco_10_external_route_stays_planning)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("route", "EXTERNAL_SERVICE");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/comparisons", tok, &body));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["route"].get_str(), "EXTERNAL_SERVICE");
}

BOOST_AUTO_TEST_SUITE_END()
