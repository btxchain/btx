// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_v2_netting_capacity_report.h>

#include <boost/test/unit_test.hpp>

#include <stdexcept>

namespace btx::test::shieldedv2netting {
namespace {

BOOST_AUTO_TEST_SUITE(shielded_v2_netting_capacity_report_tests)

BOOST_AUTO_TEST_CASE(capacity_report_rejects_invalid_config)
{
    RuntimeReportConfig config;
    config.measured_iterations = 0;
    config.scenarios = {RuntimeScenarioConfig{2, 5000}};
    BOOST_CHECK_THROW(BuildRuntimeReport(config), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(capacity_report_matches_two_domain_sensitivity_case)
{
    RuntimeReportConfig config;
    config.measured_iterations = 2;
    config.pair_gross_flow_sat = COIN;
    config.scenarios = {RuntimeScenarioConfig{2, 5000}};

    const UniValue report = BuildRuntimeReport(config);
    const UniValue& scenarios = report.find_value("scenarios").get_array();
    BOOST_REQUIRE_EQUAL(scenarios.size(), 1U);

    const UniValue& scenario = scenarios[0].get_obj();
    BOOST_CHECK_EQUAL(scenario.find_value("domain_count").getInt<int64_t>(), 2);
    BOOST_CHECK_EQUAL(scenario.find_value("pairwise_cancellation_bps").getInt<int64_t>(), 5000);

    const UniValue& achieved = scenario.find_value("achieved_netting_bps_summary").get_obj();
    BOOST_CHECK_EQUAL(achieved.find_value("median").getInt<int64_t>(), 5000);

    const UniValue& multiplier =
        scenario.find_value("effective_capacity_multiplier_milli_summary").get_obj();
    BOOST_CHECK_EQUAL(multiplier.find_value("median").getInt<int64_t>(), 2000);

    const UniValue& peak = scenario.find_value("peak_window").get_obj();
    BOOST_CHECK_EQUAL(peak.find_value("manifest_domain_count").getInt<int64_t>(), 2);
    BOOST_CHECK_EQUAL(peak.find_value("reserve_output_count").getInt<int64_t>(), 1);
}

BOOST_AUTO_TEST_CASE(capacity_report_shows_multilateral_gain_and_builds_representative_transactions)
{
    RuntimeReportConfig config;
    config.measured_iterations = 3;
    config.scenarios = {RuntimeScenarioConfig{8, 8000}};

    const UniValue report = BuildRuntimeReport(config);
    const UniValue& scenario = report.find_value("scenarios")[0].get_obj();

    const UniValue& achieved = scenario.find_value("achieved_netting_bps_summary").get_obj();
    BOOST_CHECK_GE(achieved.find_value("median").getInt<int64_t>(), 8000);

    const UniValue& peak = scenario.find_value("peak_window").get_obj();
    BOOST_CHECK_EQUAL(peak.find_value("manifest_domain_count").getInt<int64_t>(), 8);
    BOOST_CHECK_GT(peak.find_value("reserve_output_count").getInt<int64_t>(), 0);

    const UniValue& rebalance = peak.find_value("representative_rebalance_tx").get_obj();
    const UniValue& settlement = peak.find_value("representative_settlement_anchor_tx").get_obj();
    BOOST_CHECK_GT(rebalance.find_value("serialized_size_bytes").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(settlement.find_value("serialized_size_bytes").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(peak.find_value("representative_rebalance_validation_ns").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(peak.find_value("representative_settlement_anchor_validation_ns").getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace
} // namespace btx::test::shieldedv2netting
