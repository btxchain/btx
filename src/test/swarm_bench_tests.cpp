// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_bench.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cmath>
#include <limits>

BOOST_FIXTURE_TEST_SUITE(swarm_bench_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_device_is_bench)
{
    modelnet::SwarmBenchSample sample;
    sample.device = "";
    sample.workload = "add";
    sample.tokens_per_sec = 10;
    sample.vram_bytes = 1000;
    sample.measurement_taken = true;
    std::string err;
    const modelnet::SwarmBenchRecord record = modelnet::SwarmRecordBench(sample, err);
    BOOST_CHECK(!record.recorded);
    BOOST_CHECK(!record.multiplier_published);
    BOOST_CHECK_EQUAL(record.tokens_per_sec, 0);
    BOOST_CHECK_EQUAL(record.vram_bytes, 0);
    BOOST_CHECK_EQUAL(record.code, "BENCH");
    BOOST_CHECK_EQUAL(err, "BENCH");
}

BOOST_AUTO_TEST_CASE(unmeasured_nonzero_rate_stays_zero)
{
    modelnet::SwarmBenchSample sample;
    sample.device = "gpu";
    sample.workload = "add";
    sample.tokens_per_sec = 10;
    sample.vram_bytes = 1000;
    sample.measurement_taken = false;
    std::string err;
    const modelnet::SwarmBenchRecord record = modelnet::SwarmRecordBench(sample, err);
    BOOST_CHECK(!record.recorded);
    BOOST_CHECK(!record.multiplier_published);
    BOOST_CHECK_EQUAL(record.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
    BOOST_CHECK_EQUAL(record.tokens_per_sec, 0);
    BOOST_CHECK_EQUAL(record.vram_bytes, 0);
}

BOOST_AUTO_TEST_CASE(non_finite_rate_is_bench)
{
    modelnet::SwarmBenchSample sample;
    sample.device = "gpu";
    sample.workload = "add";
    sample.tokens_per_sec = std::numeric_limits<double>::quiet_NaN();
    sample.vram_bytes = 1000;
    sample.measurement_taken = true;
    std::string err;
    const modelnet::SwarmBenchRecord record = modelnet::SwarmRecordBench(sample, err);
    BOOST_CHECK(!record.recorded);
    BOOST_CHECK(!record.multiplier_published);
    BOOST_CHECK(!std::isfinite(sample.tokens_per_sec));
    BOOST_CHECK_EQUAL(record.tokens_per_sec, 0);
    BOOST_CHECK_EQUAL(record.vram_bytes, 0);
    BOOST_CHECK_EQUAL(record.code, "BENCH");
    BOOST_CHECK_EQUAL(err, "BENCH");
}

BOOST_AUTO_TEST_CASE(zero_vram_is_bench)
{
    modelnet::SwarmBenchSample sample;
    sample.device = "gpu";
    sample.workload = "add";
    sample.tokens_per_sec = 10;
    sample.vram_bytes = 0;
    sample.measurement_taken = true;
    std::string err;
    const modelnet::SwarmBenchRecord record = modelnet::SwarmRecordBench(sample, err);
    BOOST_CHECK(!record.recorded);
    BOOST_CHECK(!record.multiplier_published);
    BOOST_CHECK_EQUAL(record.tokens_per_sec, 0);
    BOOST_CHECK_EQUAL(record.vram_bytes, 0);
    BOOST_CHECK_EQUAL(record.code, "BENCH");
    BOOST_CHECK_EQUAL(err, "BENCH");
}

BOOST_AUTO_TEST_CASE(measured_sample_is_recorded)
{
    modelnet::SwarmBenchSample sample;
    sample.device = "gpu";
    sample.workload = "add";
    sample.tokens_per_sec = 10;
    sample.vram_bytes = 1000;
    sample.measurement_taken = true;
    std::string err = "prior";
    const modelnet::SwarmBenchRecord record = modelnet::SwarmRecordBench(sample, err);
    BOOST_CHECK(record.recorded);
    BOOST_CHECK(!record.multiplier_published);
    BOOST_CHECK_EQUAL(record.code, "RECORDED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(record.tokens_per_sec, 10);
    BOOST_CHECK_EQUAL(record.vram_bytes, 1000);
}

BOOST_AUTO_TEST_SUITE_END()
