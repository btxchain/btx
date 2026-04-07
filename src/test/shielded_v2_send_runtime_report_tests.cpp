// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_v2_send_runtime_report.h>
#include <test/util/setup_common.h>

#include <shielded/lattice/params.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(shielded_v2_send_runtime_report_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(runtime_report_captures_direct_send_throughput_and_capacity)
{
    const auto report = btx::test::shieldedv2send::BuildRuntimeReport({
        .warmup_iterations = 0,
        .measured_iterations = 1,
        .fee_sat = 1000,
        .scenarios = {
            {1, 2},
        },
    });

    BOOST_REQUIRE(report.isObject());
    BOOST_CHECK_EQUAL(report.find_value("format_version").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(report.find_value("report_kind").get_str(), "v2_send_throughput_runtime");

    const UniValue& runtime_config = report.find_value("runtime_config");
    BOOST_REQUIRE(runtime_config.isObject());
    BOOST_CHECK_EQUAL(runtime_config.find_value("validation_surface").get_str(), "postfork");

    const UniValue& limits = report.find_value("limits");
    BOOST_REQUIRE(limits.isObject());
    BOOST_CHECK_EQUAL(limits.find_value("ring_size").getInt<int>(),
                      static_cast<int>(shielded::lattice::RING_SIZE));
    BOOST_CHECK_EQUAL(limits.find_value("max_direct_spends").getInt<int>(), 64);
    BOOST_CHECK_EQUAL(limits.find_value("max_direct_outputs").getInt<int>(), 64);
    BOOST_CHECK_GT(limits.find_value("max_block_shielded_verify_units").getInt<int64_t>(), 0);

    const UniValue& scenarios = report.find_value("scenarios");
    BOOST_REQUIRE(scenarios.isArray());
    BOOST_REQUIRE_EQUAL(scenarios.size(), 1U);

    const UniValue& first = scenarios[0];
    BOOST_REQUIRE(first.isObject());
    BOOST_CHECK_EQUAL(first.find_value("scenario_kind").get_str(), "direct_smile_send");
    BOOST_CHECK_EQUAL(first.find_value("spend_count").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(first.find_value("output_count").getInt<int>(), 2);
    BOOST_CHECK_EQUAL(first.find_value("transparent_input_count").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(first.find_value("transparent_output_count").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(first.find_value("tree_size").getInt<int>(),
                      static_cast<int>(shielded::lattice::RING_SIZE));
    BOOST_CHECK_GT(first.find_value("total_input_value_sat").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(first.find_value("total_output_value_sat").getInt<int64_t>(), 0);

    const UniValue& first_shape = first.find_value("tx_shape");
    BOOST_REQUIRE(first_shape.isObject());
    BOOST_CHECK_GT(first_shape.find_value("serialized_size_bytes").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(first_shape.find_value("tx_weight").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(first_shape.find_value("shielded_policy_weight").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(first_shape.find_value("proof_payload_bytes").getInt<int64_t>(), 0);

    const UniValue& first_usage = first.find_value("resource_usage");
    BOOST_REQUIRE(first_usage.isObject());
    BOOST_CHECK_EQUAL(first_usage.find_value("scan_units").getInt<int>(), 2);
    BOOST_CHECK_EQUAL(first_usage.find_value("tree_update_units").getInt<int>(), 3);
    BOOST_CHECK_GT(first_usage.find_value("verify_units").getInt<int64_t>(), 0);

    const UniValue& first_capacity = first.find_value("block_capacity");
    BOOST_REQUIRE(first_capacity.isObject());
    BOOST_CHECK_EQUAL(first_capacity.find_value("binding_limit").get_str(), "serialized_size");
    BOOST_CHECK_GT(first_capacity.find_value("max_transactions_per_block").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(first_capacity.find_value("max_output_notes_per_block").getInt<int64_t>(), 0);

    const UniValue& first_policy = first.find_value("relay_policy");
    BOOST_REQUIRE(first_policy.isObject());
    BOOST_CHECK(first_policy.find_value("within_standard_policy_weight").get_bool());
    BOOST_CHECK_GT(first_policy.find_value("max_transactions_by_standard_policy_weight").getInt<int64_t>(), 0);

    const UniValue& first_build = first.find_value("build_summary");
    const UniValue& first_check = first.find_value("proof_check_summary");
    BOOST_REQUIRE(first_build.isObject());
    BOOST_REQUIRE(first_check.isObject());
    BOOST_CHECK_EQUAL(first_build.find_value("count").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(first_check.find_value("count").getInt<int>(), 1);
    BOOST_CHECK_GT(first_build.find_value("median_ns").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(first_check.find_value("median_ns").getInt<int64_t>(), 0);

    const UniValue& first_measurements = first.find_value("measurements");
    BOOST_REQUIRE(first_measurements.isArray());
    BOOST_REQUIRE_EQUAL(first_measurements.size(), 1U);
    BOOST_CHECK_GT(first_measurements[0].find_value("full_pipeline_ns").getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_CASE(runtime_report_supports_proofless_transparent_deposit_scenarios)
{
    const auto report = btx::test::shieldedv2send::BuildRuntimeReport({
        .warmup_iterations = 0,
        .measured_iterations = 1,
        .fee_sat = 1000,
        .validation_surface = btx::test::shieldedv2send::RuntimeValidationSurface::PREFORK,
        .scenarios = {
            {0, 2},
        },
    });

    const UniValue& scenarios = report.find_value("scenarios");
    BOOST_REQUIRE(scenarios.isArray());
    BOOST_REQUIRE_EQUAL(scenarios.size(), 1U);
    BOOST_CHECK_EQUAL(report.find_value("runtime_config").find_value("validation_surface").get_str(), "prefork");

    const UniValue& first = scenarios[0];
    BOOST_REQUIRE(first.isObject());
    BOOST_CHECK_EQUAL(first.find_value("scenario_kind").get_str(), "proofless_transparent_deposit");
    BOOST_CHECK_EQUAL(first.find_value("spend_count").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(first.find_value("output_count").getInt<int>(), 2);
    BOOST_CHECK_EQUAL(first.find_value("transparent_input_count").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(first.find_value("transparent_output_count").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(first.find_value("tree_size").getInt<int>(), 0);

    const UniValue& tx_shape = first.find_value("tx_shape");
    BOOST_REQUIRE(tx_shape.isObject());
    BOOST_CHECK_EQUAL(tx_shape.find_value("proof_payload_bytes").getInt<int>(), 0);

    const UniValue& usage = first.find_value("resource_usage");
    BOOST_REQUIRE(usage.isObject());
    BOOST_CHECK_EQUAL(usage.find_value("scan_units").getInt<int>(), 2);
    BOOST_CHECK_EQUAL(usage.find_value("tree_update_units").getInt<int>(), 2);
    BOOST_CHECK_EQUAL(usage.find_value("verify_units").getInt<int64_t>(), 30);
}

BOOST_AUTO_TEST_CASE(runtime_report_rejects_invalid_config)
{
    BOOST_CHECK_THROW(
        btx::test::shieldedv2send::BuildRuntimeReport({
            .warmup_iterations = 0,
            .measured_iterations = 0,
            .fee_sat = 1000,
            .scenarios = {{1, 2}},
        }),
        std::runtime_error);
    BOOST_CHECK_THROW(
        btx::test::shieldedv2send::BuildRuntimeReport({
            .warmup_iterations = 0,
            .measured_iterations = 1,
            .fee_sat = 1000,
            .scenarios = {},
        }),
        std::runtime_error);
    BOOST_CHECK_THROW(
        btx::test::shieldedv2send::BuildRuntimeReport({
            .warmup_iterations = 0,
            .measured_iterations = 1,
            .fee_sat = 1000,
            .scenarios = {{0, 0}},
        }),
        std::runtime_error);
    BOOST_CHECK_THROW(
        btx::test::shieldedv2send::BuildRuntimeReport({
            .warmup_iterations = 0,
            .measured_iterations = 1,
            .fee_sat = 1000,
            .validation_surface = btx::test::shieldedv2send::RuntimeValidationSurface::POSTFORK,
            .scenarios = {{0, 2}},
        }),
        std::runtime_error);
    BOOST_CHECK_THROW(
        btx::test::shieldedv2send::BuildRuntimeReport({
            .warmup_iterations = 0,
            .measured_iterations = 1,
            .fee_sat = -1,
            .scenarios = {{1, 2}},
        }),
        std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()
