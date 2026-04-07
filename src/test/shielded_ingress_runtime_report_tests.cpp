// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <shielded/v2_bundle.h>
#include <test/shielded_ingress_runtime_report.h>

#include <boost/test/unit_test.hpp>

namespace {

const UniValue& FindScenario(const UniValue& scenarios, int64_t leaf_count)
{
    for (size_t i = 0; i < scenarios.size(); ++i) {
        const UniValue& scenario = scenarios[i];
        if (scenario.find_value("ingress_leaf_count").getInt<int64_t>() == leaf_count) {
            return scenario;
        }
    }
    throw std::runtime_error("missing scenario");
}

} // namespace

BOOST_AUTO_TEST_SUITE(shielded_ingress_runtime_report_tests)

BOOST_AUTO_TEST_CASE(runtime_report_tracks_slice12_leaf_bands_and_bundle_limits)
{
    const auto report = btx::test::ingress::BuildRuntimeReport({
        .warmup_iterations = 0,
        .measured_iterations = 1,
        .reserve_output_count = 1,
        .leaf_counts = {100, 1000, 5000, 10000},
    });

    BOOST_REQUIRE(report.isObject());
    BOOST_CHECK_EQUAL(report.find_value("format_version").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(report.find_value("report_kind").get_str(), "v2_ingress_shard_schedule_runtime");

    const UniValue& limits = report.find_value("limits");
    BOOST_REQUIRE(limits.isObject());
    BOOST_CHECK_EQUAL(limits.find_value("max_proof_shards").getInt<int64_t>(),
                      static_cast<int64_t>(shielded::v2::MAX_PROOF_SHARDS));
    BOOST_CHECK_EQUAL(limits.find_value("max_outputs_per_proof_shard").getInt<int64_t>(), 8);

    const UniValue& scenarios = report.find_value("scenarios");
    BOOST_REQUIRE(scenarios.isArray());
    BOOST_REQUIRE_EQUAL(scenarios.size(), 4U);

    const UniValue& leaf100 = FindScenario(scenarios, 100);
    BOOST_CHECK_EQUAL(leaf100.find_value("shard_count").getInt<int64_t>(), 13);
    BOOST_CHECK(leaf100.find_value("within_bundle_proof_shard_limit").get_bool());
    BOOST_CHECK_EQUAL(leaf100.find_value("max_ingress_leaves_per_shard").getInt<int64_t>(), 8);
    BOOST_CHECK_EQUAL(leaf100.find_value("ingress_leaf_histogram").find_value("7").getInt<int64_t>(), 1);
    BOOST_CHECK_EQUAL(leaf100.find_value("ingress_leaf_histogram").find_value("8").getInt<int64_t>(), 11);
    BOOST_CHECK_EQUAL(leaf100.find_value("ingress_leaf_histogram").find_value("5").getInt<int64_t>(), 1);

    const UniValue& leaf1000 = FindScenario(scenarios, 1000);
    BOOST_CHECK_EQUAL(leaf1000.find_value("shard_count").getInt<int64_t>(), 126);
    BOOST_CHECK(leaf1000.find_value("within_bundle_proof_shard_limit").get_bool());

    const UniValue& leaf5000 = FindScenario(scenarios, 5000);
    BOOST_CHECK_EQUAL(leaf5000.find_value("shard_count").getInt<int64_t>(), 626);
    BOOST_CHECK(!leaf5000.find_value("within_bundle_proof_shard_limit").get_bool());
    BOOST_CHECK_EQUAL(leaf5000.find_value("exceeds_bundle_proof_shard_limit_by").getInt<int64_t>(), 370);

    const UniValue& leaf10000 = FindScenario(scenarios, 10000);
    BOOST_CHECK_EQUAL(leaf10000.find_value("shard_count").getInt<int64_t>(), 1251);
    BOOST_CHECK(!leaf10000.find_value("within_bundle_proof_shard_limit").get_bool());
    BOOST_CHECK_EQUAL(leaf10000.find_value("exceeds_bundle_proof_shard_limit_by").getInt<int64_t>(), 995);
}

BOOST_AUTO_TEST_CASE(runtime_report_rejects_zero_measured_iterations)
{
    BOOST_CHECK_THROW(
        btx::test::ingress::BuildRuntimeReport({
            .warmup_iterations = 0,
            .measured_iterations = 0,
            .reserve_output_count = 1,
            .leaf_counts = {100},
        }),
        std::runtime_error);
}

BOOST_AUTO_TEST_CASE(runtime_report_rejects_empty_leaf_counts)
{
    BOOST_CHECK_THROW(
        btx::test::ingress::BuildRuntimeReport({
            .warmup_iterations = 0,
            .measured_iterations = 1,
            .reserve_output_count = 1,
            .leaf_counts = {},
        }),
        std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()
