// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_ingress_proof_runtime_report.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(shielded_ingress_proof_runtime_report_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(proof_runtime_report_captures_real_ingress_build_and_check)
{
    const auto report = btx::test::ingress::BuildProofRuntimeReport({
        .warmup_iterations = 0,
        .measured_iterations = 1,
        .reserve_output_count = 1,
        .leaf_count = 4,
    });

    BOOST_REQUIRE(report.isObject());
    BOOST_CHECK_EQUAL(report.find_value("format_version").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(report.find_value("report_kind").get_str(), "v2_ingress_proof_runtime");
    BOOST_CHECK_EQUAL(report.find_value("status").get_str(), "built_and_checked");

    const UniValue& scenario = report.find_value("scenario");
    BOOST_REQUIRE(scenario.isObject());
    BOOST_CHECK_EQUAL(scenario.find_value("reserve_output_count").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(scenario.find_value("ingress_leaf_count").getInt<int>(), 4);
    BOOST_CHECK_EQUAL(scenario.find_value("proof_shard_count").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(scenario.find_value("max_total_outputs_per_shard").getInt<int>(), 5);
    BOOST_CHECK_GT(scenario.find_value("tx_shape").find_value("serialized_size_bytes").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(scenario.find_value("tx_shape").find_value("tx_weight").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(scenario.find_value("resource_usage").find_value("verify_units").getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(scenario.find_value("resource_usage").find_value("scan_units").getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(scenario.find_value("block_capacity").find_value("binding_limit").get_str(),
                      "serialized_size");
    BOOST_CHECK_GT(scenario.find_value("block_capacity").find_value("max_transactions_per_block").getInt<int64_t>(), 0);

    const UniValue& runtime_config = report.find_value("runtime_config");
    BOOST_REQUIRE(runtime_config.isObject());
    BOOST_CHECK_EQUAL(runtime_config.find_value("leaf_count").getInt<int>(), 4);
    BOOST_CHECK_EQUAL(runtime_config.find_value("backend").get_str(), "smile");
    BOOST_CHECK_EQUAL(runtime_config.find_value("settlement_witness_kind").get_str(), "proof_only");

    const UniValue& build_summary = report.find_value("build_summary");
    const UniValue& proof_check_summary = report.find_value("proof_check_summary");
    BOOST_REQUIRE(build_summary.isObject());
    BOOST_REQUIRE(proof_check_summary.isObject());
    BOOST_CHECK_EQUAL(build_summary.find_value("count").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(proof_check_summary.find_value("count").getInt<int>(), 1);
    BOOST_CHECK_GT(build_summary.find_value("min_ns").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(proof_check_summary.find_value("min_ns").getInt<int64_t>(), 0);

    const UniValue& measurements = report.find_value("measurements");
    BOOST_REQUIRE(measurements.isArray());
    BOOST_REQUIRE_EQUAL(measurements.size(), 1U);
    const UniValue& measurement = measurements[0];
    BOOST_REQUIRE(measurement.isObject());
    BOOST_CHECK_GT(measurement.find_value("build_ns").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(measurement.find_value("proof_check_ns").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(measurement.find_value("proof_payload_size").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(measurement.find_value("serialized_tx_size").getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(measurement.find_value("proof_shard_count").getInt<int>(), 1);
    BOOST_CHECK_GT(measurement.find_value("tx_weight").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(measurement.find_value("shielded_policy_weight").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(measurement.find_value("verify_units").getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(measurement.find_value("scan_units").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(measurement.find_value("tree_update_units").getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_CASE(proof_runtime_report_marks_matrict_backend_as_builder_rejected)
{
    const auto report = btx::test::ingress::BuildProofRuntimeReport({
        .backend_kind = btx::test::ingress::ProofRuntimeBackendKind::MATRICT_PLUS,
        .warmup_iterations = 0,
        .measured_iterations = 1,
        .reserve_output_count = 1,
        .leaf_count = 8,
    });

    BOOST_REQUIRE(report.isObject());
    BOOST_CHECK_EQUAL(report.find_value("report_kind").get_str(), "v2_ingress_proof_runtime");
    BOOST_CHECK_EQUAL(report.find_value("status").get_str(), "builder_rejected");

    const UniValue& runtime_config = report.find_value("runtime_config");
    BOOST_REQUIRE(runtime_config.isObject());
    BOOST_CHECK_EQUAL(runtime_config.find_value("backend").get_str(), "matrict_plus");

    const UniValue& rejection = report.find_value("rejection");
    BOOST_REQUIRE(rejection.isObject());
    BOOST_CHECK_EQUAL(rejection.find_value("reject_reason").get_str(), "bad-shielded-v2-ingress-backend");
}

BOOST_AUTO_TEST_CASE(proof_runtime_report_marks_receipt_backed_backend_as_builder_rejected)
{
    const auto report = btx::test::ingress::BuildProofRuntimeReport({
        .backend_kind = btx::test::ingress::ProofRuntimeBackendKind::RECEIPT_BACKED,
        .warmup_iterations = 0,
        .measured_iterations = 1,
        .reserve_output_count = 1,
        .leaf_count = 8,
    });

    BOOST_REQUIRE(report.isObject());
    BOOST_CHECK_EQUAL(report.find_value("report_kind").get_str(), "v2_ingress_proof_runtime");
    BOOST_CHECK_EQUAL(report.find_value("status").get_str(), "builder_rejected");

    const UniValue& runtime_config = report.find_value("runtime_config");
    BOOST_REQUIRE(runtime_config.isObject());
    BOOST_CHECK_EQUAL(runtime_config.find_value("backend").get_str(), "receipt_backed");

    const UniValue& rejection = report.find_value("rejection");
    BOOST_REQUIRE(rejection.isObject());
    BOOST_CHECK_EQUAL(rejection.find_value("reject_reason").get_str(), "bad-shielded-v2-ingress-backend");
}

BOOST_AUTO_TEST_CASE(proof_runtime_report_reports_large_receipt_backed_target_band_as_scenario_rejected)
{
    const auto report = btx::test::ingress::BuildProofRuntimeReport({
        .backend_kind = btx::test::ingress::ProofRuntimeBackendKind::RECEIPT_BACKED,
        .warmup_iterations = 0,
        .measured_iterations = 1,
        .reserve_output_count = 1,
        .leaf_count = 10000,
    });

    BOOST_REQUIRE(report.isObject());
    BOOST_CHECK_EQUAL(report.find_value("status").get_str(), "scenario_rejected");
    BOOST_CHECK_EQUAL(report.find_value("rejection").find_value("reject_reason").get_str(),
                      "invalid ingress runtime spend input count");
}

BOOST_AUTO_TEST_CASE(proof_capacity_sweep_report_tracks_successful_bands)
{
    const auto report = btx::test::ingress::BuildProofCapacitySweepReport({
        .warmup_iterations = 0,
        .measured_iterations = 1,
        .reserve_output_count = 1,
        .leaf_counts = {4, 6},
    });

    BOOST_REQUIRE(report.isObject());
    BOOST_CHECK_EQUAL(report.find_value("format_version").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(report.find_value("report_kind").get_str(), "v2_ingress_proof_capacity_sweep");
    BOOST_CHECK_EQUAL(report.find_value("status").get_str(), "all_candidates_built_and_checked");

    const UniValue& boundary = report.find_value("boundary");
    BOOST_REQUIRE(boundary.isObject());
    BOOST_CHECK_EQUAL(boundary.find_value("highest_successful_leaf_count").getInt<int>(), 6);
    BOOST_CHECK(boundary.find_value("lowest_rejected_leaf_count").isNull());

    const UniValue& bands = report.find_value("bands");
    BOOST_REQUIRE(bands.isArray());
    BOOST_REQUIRE_EQUAL(bands.size(), 2U);
    BOOST_CHECK_EQUAL(bands[0].find_value("leaf_count").getInt<int>(), 4);
    BOOST_CHECK_EQUAL(bands[0].find_value("status").get_str(), "built_and_checked");
    BOOST_CHECK_GT(bands[0].find_value("proof_payload_size").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(bands[0].find_value("tx_weight").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(bands[0].find_value("verify_units").getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(bands[0].find_value("binding_limit").get_str(), "serialized_size");
    BOOST_CHECK_GT(bands[0].find_value("max_transactions_per_block").getInt<int64_t>(), 0);
    BOOST_REQUIRE(bands[0].find_value("binding_limit").isStr());
    BOOST_CHECK_EQUAL(bands[1].find_value("leaf_count").getInt<int>(), 6);
}

BOOST_AUTO_TEST_CASE(proof_backend_decision_report_tracks_large_target_as_within_payload_budget)
{
    const auto report = btx::test::ingress::BuildProofBackendDecisionReport({
        .warmup_iterations = 0,
        .measured_iterations = 1,
        .reserve_output_count = 1,
        .measured_leaf_counts = {4},
        .target_leaf_counts = {100},
    });

    BOOST_REQUIRE(report.isObject());
    BOOST_CHECK_EQUAL(report.find_value("format_version").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(report.find_value("report_kind").get_str(), "v2_ingress_proof_backend_decision");
    BOOST_CHECK_EQUAL(report.find_value("status").get_str(), "selected_backend_within_target_range");

    const UniValue& target_bands = report.find_value("target_bands");
    BOOST_REQUIRE(target_bands.isArray());
    BOOST_REQUIRE_EQUAL(target_bands.size(), 1U);
    const UniValue& target = target_bands[0];
    BOOST_REQUIRE(target.isObject());
    BOOST_CHECK_EQUAL(target.find_value("leaf_count").getInt<int>(), 100);
    BOOST_CHECK_EQUAL(target.find_value("status").get_str(), "selected_backend_within_bundle_payload_budget");
    BOOST_CHECK_LT(target.find_value("required_reduction_factor_vs_best_success_avg_shard_payload").get_real(), 1.0);
}

BOOST_AUTO_TEST_CASE(proof_backend_decision_report_rejects_receipt_backend_without_successful_measured_bands)
{
    BOOST_CHECK_THROW(
        btx::test::ingress::BuildProofBackendDecisionReport({
            .backend_kind = btx::test::ingress::ProofRuntimeBackendKind::RECEIPT_BACKED,
            .warmup_iterations = 0,
            .measured_iterations = 1,
            .reserve_output_count = 1,
            .measured_leaf_counts = {100},
            .target_leaf_counts = {10000},
        }),
        std::runtime_error);
}

BOOST_AUTO_TEST_CASE(proof_runtime_report_rejects_zero_measured_iterations)
{
    BOOST_CHECK_THROW(
        btx::test::ingress::BuildProofRuntimeReport({
            .warmup_iterations = 0,
            .measured_iterations = 0,
            .reserve_output_count = 1,
            .leaf_count = 4,
        }),
        std::runtime_error);
}

BOOST_AUTO_TEST_CASE(proof_runtime_report_rejects_zero_leaf_count)
{
    BOOST_CHECK_THROW(
        btx::test::ingress::BuildProofRuntimeReport({
            .warmup_iterations = 0,
            .measured_iterations = 1,
            .reserve_output_count = 1,
            .leaf_count = 0,
        }),
        std::runtime_error);
}

BOOST_AUTO_TEST_CASE(proof_runtime_report_reports_receipt_backed_shard_cap_rejection)
{
    const auto report = btx::test::ingress::BuildProofRuntimeReport({
        .backend_kind = btx::test::ingress::ProofRuntimeBackendKind::RECEIPT_BACKED,
        .warmup_iterations = 0,
        .measured_iterations = 1,
        .reserve_output_count = 1,
        .leaf_count = 16384,
    });

    BOOST_REQUIRE(report.isObject());
    BOOST_CHECK_EQUAL(report.find_value("status").get_str(), "scenario_rejected");

    const UniValue& scenario = report.find_value("scenario");
    BOOST_REQUIRE(scenario.isObject());
    BOOST_CHECK_EQUAL(scenario.find_value("proof_shard_count").getInt<int>(), 257);

    const UniValue& rejection = report.find_value("rejection");
    BOOST_REQUIRE(rejection.isObject());
    BOOST_CHECK_EQUAL(rejection.find_value("reject_reason").get_str(), "scenario exceeds max proof shards");
}

BOOST_AUTO_TEST_CASE(proof_capacity_sweep_report_rejects_empty_leaf_counts)
{
    BOOST_CHECK_THROW(
        btx::test::ingress::BuildProofCapacitySweepReport({
            .warmup_iterations = 0,
            .measured_iterations = 1,
            .reserve_output_count = 1,
            .leaf_counts = {},
        }),
        std::runtime_error);
}

BOOST_AUTO_TEST_CASE(proof_backend_decision_report_rejects_empty_target_leaf_counts)
{
    BOOST_CHECK_THROW(
        btx::test::ingress::BuildProofBackendDecisionReport({
            .warmup_iterations = 0,
            .measured_iterations = 1,
            .reserve_output_count = 1,
            .measured_leaf_counts = {4},
            .target_leaf_counts = {},
        }),
        std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()
