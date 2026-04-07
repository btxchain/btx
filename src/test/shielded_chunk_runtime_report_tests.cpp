// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_chunk_runtime_report.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(shielded_chunk_runtime_report_tests)

BOOST_AUTO_TEST_CASE(runtime_report_captures_large_fanout_chunk_discovery_invariants)
{
    const auto report = btx::test::shieldedv2chunk::BuildRuntimeReport({
        .warmup_iterations = 0,
        .measured_iterations = 1,
        .output_count = 256,
        .outputs_per_chunk = 32,
    });

    BOOST_REQUIRE(report.isObject());
    BOOST_CHECK_EQUAL(report.find_value("format_version").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(report.find_value("report_kind").get_str(), "shielded_v2_chunk_discovery_runtime");

    const UniValue& fixture = report.find_value("fixture");
    BOOST_REQUIRE(fixture.isObject());
    BOOST_CHECK_EQUAL(fixture.find_value("output_count").getInt<int>(), 256);
    BOOST_CHECK_EQUAL(fixture.find_value("output_chunk_count").getInt<int>(), 8);
    BOOST_CHECK_EQUAL(fixture.find_value("outputs_per_chunk").getInt<int>(), 32);
    BOOST_CHECK_EQUAL(fixture.find_value("scan_domain").get_str(), "opaque");
    BOOST_CHECK_GT(fixture.find_value("owned_output_count").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(fixture.find_value("owned_chunk_count").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(fixture.find_value("total_ciphertext_bytes").getInt<int64_t>(), 0);

    const UniValue& measurements = report.find_value("measurements");
    BOOST_REQUIRE(measurements.isArray());
    BOOST_REQUIRE_EQUAL(measurements.size(), 1U);

    const UniValue& sample = measurements[0];
    BOOST_REQUIRE(sample.isObject());
    BOOST_CHECK_EQUAL(sample.find_value("output_count").getInt<int>(), 256);
    BOOST_CHECK_EQUAL(sample.find_value("output_chunk_count").getInt<int>(), 8);
    BOOST_CHECK_EQUAL(sample.find_value("owned_output_count").getInt<int64_t>(),
                      fixture.find_value("owned_output_count").getInt<int64_t>());
    BOOST_CHECK_EQUAL(sample.find_value("owned_chunk_count").getInt<int64_t>(),
                      fixture.find_value("owned_chunk_count").getInt<int64_t>());
    BOOST_CHECK_EQUAL(sample.find_value("successful_decrypt_count").getInt<int64_t>(),
                      fixture.find_value("owned_output_count").getInt<int64_t>());
    BOOST_CHECK_EQUAL(sample.find_value("hint_match_count").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(sample.find_value("false_positive_hint_count").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(sample.find_value("skipped_decrypt_attempt_count").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(sample.find_value("canonicality_check_ns").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(sample.find_value("output_discovery_ns").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(sample.find_value("chunk_summary_ns").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(sample.find_value("full_pipeline_ns").getInt<int64_t>(), 0);

    const UniValue& skipped = report.find_value("skipped_decrypt_attempt_summary");
    BOOST_REQUIRE(skipped.isObject());
    BOOST_CHECK_EQUAL(skipped.find_value("count").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(skipped.find_value("min").getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_CASE(runtime_report_rejects_invalid_config)
{
    BOOST_CHECK_THROW(
        btx::test::shieldedv2chunk::BuildRuntimeReport({
            .warmup_iterations = 0,
            .measured_iterations = 0,
            .output_count = 256,
            .outputs_per_chunk = 32,
        }),
        std::runtime_error);
    BOOST_CHECK_THROW(
        btx::test::shieldedv2chunk::BuildRuntimeReport({
            .warmup_iterations = 0,
            .measured_iterations = 1,
            .output_count = 256,
            .outputs_per_chunk = 0,
        }),
        std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()
