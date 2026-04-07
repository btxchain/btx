// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_v2_egress_runtime_report.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(shielded_v2_egress_runtime_report_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(runtime_report_captures_real_egress_build_validation_and_scan)
{
    const auto report = btx::test::shieldedv2egress::BuildRuntimeReport({
        .warmup_iterations = 0,
        .measured_iterations = 1,
        .scenarios = {
            {3, 2},
        },
    });

    BOOST_REQUIRE(report.isObject());
    BOOST_CHECK_EQUAL(report.find_value("format_version").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(report.find_value("report_kind").get_str(), "v2_egress_validation_runtime");

    const UniValue& limits = report.find_value("limits");
    BOOST_REQUIRE(limits.isObject());
    BOOST_CHECK_GT(limits.find_value("max_egress_outputs").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(limits.find_value("max_output_chunks").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(limits.find_value("max_block_shielded_scan_units").getInt<int64_t>(), 0);

    const UniValue& scenarios = report.find_value("scenarios");
    BOOST_REQUIRE(scenarios.isArray());
    BOOST_REQUIRE_EQUAL(scenarios.size(), 1U);

    const UniValue& first = scenarios[0];
    BOOST_REQUIRE(first.isObject());
    BOOST_CHECK_EQUAL(first.find_value("output_count").getInt<int>(), 3);
    BOOST_CHECK_EQUAL(first.find_value("outputs_per_chunk").getInt<int>(), 2);
    BOOST_CHECK_EQUAL(first.find_value("output_chunk_count").getInt<int>(), 1);
    BOOST_CHECK_GT(first.find_value("owned_output_count").getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(first.find_value("owned_chunk_count").getInt<int>(), 1);

    const UniValue& tx_shape = first.find_value("tx_shape");
    BOOST_REQUIRE(tx_shape.isObject());
    BOOST_CHECK_GT(tx_shape.find_value("serialized_size_bytes").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(tx_shape.find_value("tx_weight").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(tx_shape.find_value("shielded_policy_weight").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(tx_shape.find_value("proof_payload_bytes").getInt<int64_t>(), 0);

    const UniValue& usage = first.find_value("resource_usage");
    BOOST_REQUIRE(usage.isObject());
    BOOST_CHECK_GT(usage.find_value("verify_units").getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(usage.find_value("scan_units").getInt<int>(), 4);
    BOOST_CHECK_EQUAL(usage.find_value("tree_update_units").getInt<int>(), 3);

    const UniValue& relay_policy = first.find_value("relay_policy");
    BOOST_REQUIRE(relay_policy.isObject());
    BOOST_CHECK(relay_policy.find_value("is_standard_tx").get_bool());
    BOOST_CHECK(relay_policy.find_value("within_standard_tx_weight").get_bool());
    BOOST_CHECK(relay_policy.find_value("within_standard_shielded_policy_weight").get_bool());

    const UniValue& block_capacity = first.find_value("block_capacity");
    BOOST_REQUIRE(block_capacity.isObject());
    BOOST_CHECK_GT(block_capacity.find_value("max_transactions_per_block").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(block_capacity.find_value("max_output_notes_per_block").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(block_capacity.find_value("max_output_chunks_per_block").getInt<int64_t>(), 0);

    const UniValue& build_statement = first.find_value("build_statement_summary");
    const UniValue& derive_outputs = first.find_value("derive_outputs_summary");
    const UniValue& build_bundle = first.find_value("build_bundle_summary");
    const UniValue& proof_check = first.find_value("proof_check_summary");
    const UniValue& output_discovery = first.find_value("output_discovery_summary");
    const UniValue& chunk_summary = first.find_value("chunk_summary");
    const UniValue& full_pipeline = first.find_value("full_pipeline_summary");
    BOOST_REQUIRE(build_statement.isObject());
    BOOST_REQUIRE(derive_outputs.isObject());
    BOOST_REQUIRE(build_bundle.isObject());
    BOOST_REQUIRE(proof_check.isObject());
    BOOST_REQUIRE(output_discovery.isObject());
    BOOST_REQUIRE(chunk_summary.isObject());
    BOOST_REQUIRE(full_pipeline.isObject());
    BOOST_CHECK_EQUAL(build_statement.find_value("count").getInt<int>(), 1);
    BOOST_CHECK_GT(build_statement.find_value("median_ns").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(proof_check.find_value("median_ns").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(output_discovery.find_value("median_ns").getInt<int64_t>(), 0);

    const UniValue& measurements = first.find_value("measurements");
    BOOST_REQUIRE(measurements.isArray());
    BOOST_REQUIRE_EQUAL(measurements.size(), 1U);
    const UniValue& measurement = measurements[0];
    BOOST_REQUIRE(measurement.isObject());
    BOOST_CHECK_GT(measurement.find_value("full_pipeline_ns").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(measurement.find_value("successful_decrypt_count").getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_CASE(runtime_report_rejects_invalid_config)
{
    BOOST_CHECK_THROW(
        btx::test::shieldedv2egress::BuildRuntimeReport({
            .warmup_iterations = 0,
            .measured_iterations = 0,
            .scenarios = {{3, 2}},
        }),
        std::runtime_error);
    BOOST_CHECK_THROW(
        btx::test::shieldedv2egress::BuildRuntimeReport({
            .warmup_iterations = 0,
            .measured_iterations = 1,
            .scenarios = {},
        }),
        std::runtime_error);
    BOOST_CHECK_THROW(
        btx::test::shieldedv2egress::BuildRuntimeReport({
            .warmup_iterations = 0,
            .measured_iterations = 1,
            .scenarios = {{0, 2}},
        }),
        std::runtime_error);
    BOOST_CHECK_THROW(
        btx::test::shieldedv2egress::BuildRuntimeReport({
            .warmup_iterations = 0,
            .measured_iterations = 1,
            .scenarios = {{3, 0}},
        }),
        std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()
