// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_v2_chain_growth_projection_report.h>

#include <boost/test/unit_test.hpp>

namespace btx::test::shieldedv2growth {
namespace {

RuntimeReportConfig BuildConfig()
{
    RuntimeReportConfig config;
    config.block_interval_seconds = 90;
    config.state_retention.retain_commitment_index = false;
    config.state_retention.retain_nullifier_index = true;
    config.state_retention.snapshot_include_commitments = false;
    config.state_retention.snapshot_include_nullifiers = true;
    config.state_retention.snapshot_target_bytes = 32'000;

    config.families = {
        FamilyFootprint{RepresentativeFamily::DIRECT_SEND, 100, 100, 10, 1, 2, 1, 2, 1},
        FamilyFootprint{RepresentativeFamily::INGRESS_BATCH, 500, 500, 40, 0, 2, 10, 1, 1},
        FamilyFootprint{RepresentativeFamily::EGRESS_BATCH, 400, 400, 30, 4, 4, 20, 20, 0},
        FamilyFootprint{RepresentativeFamily::REBALANCE, 200, 200, 20, 0, 1, 0, 1, 0},
        FamilyFootprint{RepresentativeFamily::SETTLEMENT_ANCHOR, 100, 100, 10, 0, 0, 0, 0, 0},
    };
    config.block_limits = {
        BlockLimitConfig{"tiny", 1'000, 1'000, 100, 20, 20},
        BlockLimitConfig{"small", 2'000, 2'000, 200, 40, 40},
    };
    config.workloads = {
        WorkloadScenarioConfig{"sample", 1'000, 2'000, 5'000, 3'000, 10},
    };
    return config;
}

} // namespace

BOOST_AUTO_TEST_SUITE(shielded_v2_chain_growth_projection_report_tests)

BOOST_AUTO_TEST_CASE(report_emits_expected_state_growth_and_block_scaling)
{
    const UniValue report = BuildRuntimeReport(BuildConfig());
    BOOST_CHECK_EQUAL(report.find_value("report_kind").get_str(), "v2_chain_growth_projection");

    const UniValue& workloads = report.find_value("workloads");
    BOOST_REQUIRE_EQUAL(workloads.size(), 1U);

    const UniValue& workload = workloads[0];
    const UniValue& tx_counts = workload.find_value("tx_counts_per_day");
    BOOST_CHECK_EQUAL(tx_counts.find_value("direct_send").getInt<int>(), 200);
    BOOST_CHECK_EQUAL(tx_counts.find_value("ingress_batch").getInt<int>(), 50);
    BOOST_CHECK_EQUAL(tx_counts.find_value("egress_batch").getInt<int>(), 15);
    BOOST_CHECK_EQUAL(tx_counts.find_value("rebalance").getInt<int>(), 10);
    BOOST_CHECK_EQUAL(tx_counts.find_value("settlement_anchor").getInt<int>(), 10);

    const UniValue& state = workload.find_value("state_growth");
    BOOST_CHECK_EQUAL(state.find_value("commitments_per_day").getInt<int>(), 760);
    BOOST_CHECK_EQUAL(state.find_value("nullifiers_per_day").getInt<int>(), 250);
    BOOST_CHECK_EQUAL(state.find_value("retained_index_bytes_per_day").getInt<int>(), 8'500);
    BOOST_CHECK_EQUAL(state.find_value("snapshot_appendix_bytes_per_day").getInt<int>(), 8'000);
    BOOST_CHECK_EQUAL(state.find_value("bounded_anchor_history_bytes_per_day").getInt<int>(), 8'000);
    BOOST_CHECK_EQUAL(state.find_value("retained_state_bytes_per_day").getInt<int>(), 24'500);
    BOOST_CHECK_EQUAL(state.find_value("snapshot_target_days").getInt<int>(), 4);

    const UniValue& projections = workload.find_value("block_limit_projections");
    BOOST_REQUIRE_EQUAL(projections.size(), 2U);

    const UniValue& tiny = projections[0];
    const UniValue& small = projections[1];
    BOOST_CHECK_EQUAL(tiny.find_value("block_limit").get_str(), "tiny");
    BOOST_CHECK_EQUAL(small.find_value("block_limit").get_str(), "small");
    BOOST_CHECK_GT(small.find_value("capacity_at_cadence")
                       .find_value("max_boundary_actions_per_day_at_cadence")
                       .getInt<int64_t>(),
                   tiny.find_value("capacity_at_cadence")
                       .find_value("max_boundary_actions_per_day_at_cadence")
                       .getInt<int64_t>());
    BOOST_CHECK_LT(small.find_value("required_blocks_per_day").find_value("max").getInt<int64_t>(),
                   tiny.find_value("required_blocks_per_day").find_value("max").getInt<int64_t>());
}

BOOST_AUTO_TEST_CASE(report_rejects_incomplete_boundary_mix)
{
    auto config = BuildConfig();
    config.workloads[0].egress_batch_share_bps = 2'999;
    BOOST_CHECK_THROW(BuildRuntimeReport(config), std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace btx::test::shieldedv2growth
