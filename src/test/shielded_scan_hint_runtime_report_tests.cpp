// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_scan_hint_runtime_report.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(shielded_scan_hint_runtime_report_tests)

BOOST_AUTO_TEST_CASE(runtime_report_records_legacy_collision_and_v2_rejection)
{
    const auto report = btx::test::shieldedv2scan::BuildRuntimeReport({
        .warmup_iterations = 0,
        .measured_iterations = 1,
        .minimum_candidate_keys = 256,
    });

    BOOST_REQUIRE(report.isObject());
    BOOST_CHECK_EQUAL(report.find_value("format_version").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(report.find_value("report_kind").get_str(), "shielded_v2_scan_hint_runtime");

    const UniValue& fixture = report.find_value("fixture");
    BOOST_REQUIRE(fixture.isObject());
    BOOST_CHECK_GE(fixture.find_value("candidate_key_count").getInt<int64_t>(), 256);
    BOOST_CHECK_EQUAL(fixture.find_value("scan_domain").get_str(), "opaque");
    BOOST_CHECK_EQUAL(fixture.find_value("scan_hint_version").getInt<int>(), 1);

    const UniValue& measurements = report.find_value("measurements");
    BOOST_REQUIRE(measurements.isArray());
    BOOST_REQUIRE_EQUAL(measurements.size(), 1U);

    const UniValue& sample = measurements[0];
    BOOST_REQUIRE(sample.isObject());
    BOOST_CHECK_EQUAL(sample.find_value("legacy_successful_decrypt_count").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(sample.find_value("v2_successful_decrypt_count").getInt<int>(), 1);
    BOOST_CHECK_GT(sample.find_value("legacy_false_positive_view_tag_count").getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(sample.find_value("v2_hint_match_count").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(sample.find_value("v2_false_positive_hint_count").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(sample.find_value("v2_wrong_domain_match_count").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(sample.find_value("avoided_decrypt_attempts").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(sample.find_value("legacy_scan_ns").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(sample.find_value("v2_scan_ns").getInt<int64_t>(), 0);

    const UniValue& avoided = report.find_value("avoided_decrypt_attempt_summary");
    BOOST_REQUIRE(avoided.isObject());
    BOOST_CHECK_EQUAL(avoided.find_value("count").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(avoided.find_value("min").getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_CASE(runtime_report_rejects_zero_measured_iterations)
{
    BOOST_CHECK_THROW(
        btx::test::shieldedv2scan::BuildRuntimeReport({
            .warmup_iterations = 0,
            .measured_iterations = 0,
            .minimum_candidate_keys = 256,
        }),
        std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()
