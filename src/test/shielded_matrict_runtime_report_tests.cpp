// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <shielded/matrict_plus_backend.h>
#include <test/shielded_matrict_runtime_report.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(shielded_matrict_runtime_report_tests)

BOOST_AUTO_TEST_CASE(runtime_report_matches_reference_vector_and_records_samples)
{
    const auto report = btx::test::matrictplus::BuildRuntimeReport({
        .warmup_iterations = 0,
        .measured_iterations = 1,
    });

    BOOST_REQUIRE(report.isObject());
    BOOST_CHECK_EQUAL(report.find_value("format_version").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(report.find_value("report_kind").get_str(), "matrict_plus_runtime");
    BOOST_CHECK_EQUAL(report.find_value("backend_id_hex").get_str(),
                      shielded::matrictplus::GetBackendId().GetHex());

    const UniValue& proof = report.find_value("proof");
    BOOST_REQUIRE(proof.isObject());
    BOOST_CHECK_EQUAL(proof.find_value("serialized_size").getInt<int64_t>(), 1066617);
    BOOST_CHECK_EQUAL(proof.find_value("serialized_proof_hash_hex").get_str(),
                      "3eb5f6bc80132decd18fb678ca1a22d5caa1effdb7cef1bc29acab96e91e7051");
    BOOST_CHECK(proof.find_value("reference_vector_match").get_bool());

    const UniValue& runtime_config = report.find_value("runtime_config");
    BOOST_REQUIRE(runtime_config.isObject());
    BOOST_CHECK_EQUAL(runtime_config.find_value("warmup_iterations").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(runtime_config.find_value("measured_iterations").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(runtime_config.find_value("duration_unit").get_str(), "nanoseconds");

    const UniValue& measurements = report.find_value("measurements");
    BOOST_REQUIRE(measurements.isArray());
    BOOST_REQUIRE_EQUAL(measurements.size(), 1U);

    const UniValue& measurement = measurements[0];
    BOOST_REQUIRE(measurement.isObject());
    BOOST_CHECK_GT(measurement.find_value("create_ns").getInt<int64_t>(), 0);
    BOOST_CHECK_GT(measurement.find_value("verify_ns").getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(measurement.find_value("serialized_size").getInt<int64_t>(), 1066617);
    BOOST_CHECK_EQUAL(measurement.find_value("serialized_proof_hash_hex").get_str(),
                      "3eb5f6bc80132decd18fb678ca1a22d5caa1effdb7cef1bc29acab96e91e7051");

    const UniValue& create_summary = report.find_value("create_summary");
    const UniValue& verify_summary = report.find_value("verify_summary");
    BOOST_REQUIRE(create_summary.isObject());
    BOOST_REQUIRE(verify_summary.isObject());
    BOOST_CHECK_EQUAL(create_summary.find_value("count").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(verify_summary.find_value("count").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(create_summary.find_value("min_ns").getInt<int64_t>(),
                      create_summary.find_value("max_ns").getInt<int64_t>());
    BOOST_CHECK_EQUAL(verify_summary.find_value("min_ns").getInt<int64_t>(),
                      verify_summary.find_value("max_ns").getInt<int64_t>());
}

BOOST_AUTO_TEST_CASE(runtime_report_rejects_zero_measured_iterations)
{
    BOOST_CHECK_THROW(
        btx::test::matrictplus::BuildRuntimeReport({
            .warmup_iterations = 0,
            .measured_iterations = 0,
        }),
        std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()
