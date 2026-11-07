// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_measure/swarm_measure.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace {

void ExpectQuiet(const modelnet::SwarmMeasure& measure)
{
    BOOST_CHECK(!measure.gpu_measured());
    BOOST_CHECK(!measure.gpu_passed());
    BOOST_CHECK(!measure.windows_passed());
    BOOST_CHECK(!measure.launched());
    BOOST_CHECK(!measure.gpu());
    BOOST_CHECK(!measure.broadcast());
    BOOST_CHECK_EQUAL(measure.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(measure.bytes_moved(), static_cast<int64_t>(0));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_measure_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(percentiles_of_the_five_sample_list)
{
    const std::vector<int64_t> samples{10, 20, 30, 40, 50};
    constexpr int64_t count = 5;
    constexpr int64_t p95_index = (count - 1) * 95 / 100;

    BOOST_CHECK_EQUAL(p95_index, static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(samples[static_cast<std::size_t>(p95_index)], static_cast<int64_t>(40));

    modelnet::SwarmMeasure measure;
    std::string err = "prior";
    BOOST_REQUIRE(measure.Measure(samples, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(measure.local_measured());
    BOOST_CHECK_EQUAL(measure.count(), count);
    BOOST_CHECK_EQUAL(measure.min_ms(), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(measure.max_ms(), static_cast<int64_t>(50));
    BOOST_CHECK_EQUAL(measure.p50(), static_cast<int64_t>(30));
    BOOST_CHECK_EQUAL(measure.p95(), static_cast<int64_t>(40));
    ExpectQuiet(measure);

    const std::vector<int64_t> shuffled{50, 10, 40, 20, 30};
    modelnet::SwarmMeasure sorted;
    BOOST_REQUIRE(sorted.Measure(shuffled, err));
    BOOST_CHECK(sorted.local_measured());
    BOOST_CHECK_EQUAL(sorted.count(), count);
    BOOST_CHECK_EQUAL(sorted.min_ms(), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(sorted.max_ms(), static_cast<int64_t>(50));
    BOOST_CHECK_EQUAL(sorted.p50(), static_cast<int64_t>(30));
    BOOST_CHECK_EQUAL(sorted.p95(), static_cast<int64_t>(40));
    ExpectQuiet(sorted);

    const std::vector<int64_t> even_count{10, 20, 30, 40};
    modelnet::SwarmMeasure even;
    BOOST_REQUIRE(even.Measure(even_count, err));
    BOOST_CHECK_EQUAL(even.count(), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(even.p50(), static_cast<int64_t>(20));
    BOOST_CHECK_EQUAL(even.p95(), even_count[static_cast<std::size_t>((4 - 1) * 95 / 100)]);
    BOOST_CHECK_EQUAL(even.p95(), static_cast<int64_t>(30));
    ExpectQuiet(even);
}

BOOST_AUTO_TEST_CASE(negative_sample_stores_nothing)
{
    modelnet::SwarmMeasure measure;
    std::string err = "prior";
    const std::vector<int64_t> samples{10, -1, 30};
    BOOST_CHECK(!measure.Measure(samples, err));
    BOOST_CHECK_EQUAL(err, "MEASURE");
    BOOST_CHECK(!measure.local_measured());
    BOOST_CHECK_EQUAL(measure.count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(measure.min_ms(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(measure.max_ms(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(measure.p50(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(measure.p95(), static_cast<int64_t>(0));
    ExpectQuiet(measure);

    BOOST_CHECK(!measure.Measure({}, err));
    BOOST_CHECK_EQUAL(err, "MEASURE");
    BOOST_CHECK(!measure.local_measured());
    BOOST_CHECK_EQUAL(measure.count(), static_cast<int64_t>(0));

    const std::vector<int64_t> stored{10, 20, 30, 40, 50};
    BOOST_REQUIRE(measure.Measure(stored, err));
    BOOST_CHECK(measure.local_measured());
    BOOST_CHECK_EQUAL(measure.p50(), static_cast<int64_t>(30));
    BOOST_CHECK_EQUAL(measure.p95(), static_cast<int64_t>(40));

    BOOST_CHECK(!measure.Measure(samples, err));
    BOOST_CHECK_EQUAL(err, "MEASURE");
    BOOST_CHECK(measure.local_measured());
    BOOST_CHECK_EQUAL(measure.count(), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(measure.p50(), static_cast<int64_t>(30));
    BOOST_CHECK_EQUAL(measure.p95(), static_cast<int64_t>(40));
    ExpectQuiet(measure);
}

BOOST_AUTO_TEST_CASE(windows_passed_stays_false_for_empty_and_stored_evidence)
{
    modelnet::SwarmMeasure measure;
    std::string err = "prior";

    BOOST_CHECK(!measure.Platform("windows", "", err));
    BOOST_CHECK_EQUAL(err, "WINDOWS_ABSENT");
    BOOST_CHECK(!measure.windows_passed());
    BOOST_CHECK(measure.platform_name().empty());
    BOOST_CHECK(measure.platform_evidence().empty());
    ExpectQuiet(measure);

    BOOST_REQUIRE(measure.Platform("windows", "compiler-log", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(measure.platform_name(), "windows");
    BOOST_CHECK_EQUAL(measure.platform_evidence(), "compiler-log");
    BOOST_CHECK(!measure.windows_passed());
    ExpectQuiet(measure);

    BOOST_CHECK(!measure.Platform("windows", "", err));
    BOOST_CHECK_EQUAL(err, "WINDOWS_ABSENT");
    BOOST_CHECK_EQUAL(measure.platform_name(), "windows");
    BOOST_CHECK_EQUAL(measure.platform_evidence(), "compiler-log");
    BOOST_CHECK(!measure.windows_passed());
    ExpectQuiet(measure);
}

BOOST_AUTO_TEST_CASE(linux_stores_evidence_and_other_names_do_not)
{
    modelnet::SwarmMeasure measure;
    std::string err = "prior";

    BOOST_CHECK(!measure.Platform("", "compiler-log", err));
    BOOST_CHECK_EQUAL(err, "PLATFORM");
    BOOST_CHECK(measure.platform_name().empty());

    BOOST_CHECK(!measure.Platform("linux", "", err));
    BOOST_CHECK_EQUAL(err, "EVIDENCE");
    BOOST_CHECK(measure.platform_name().empty());
    BOOST_CHECK(measure.platform_evidence().empty());

    BOOST_REQUIRE(measure.Platform("linux", "local-log", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(measure.platform_name(), "linux");
    BOOST_CHECK_EQUAL(measure.platform_evidence(), "local-log");
    BOOST_CHECK(!measure.windows_passed());
    BOOST_CHECK(!measure.local_measured());
    ExpectQuiet(measure);

    BOOST_CHECK(!measure.Platform("other", "local-log", err));
    BOOST_CHECK_EQUAL(err, "PLATFORM");
    BOOST_CHECK_EQUAL(measure.platform_name(), "linux");
    BOOST_CHECK_EQUAL(measure.platform_evidence(), "local-log");
    ExpectQuiet(measure);
}

BOOST_AUTO_TEST_SUITE_END()
