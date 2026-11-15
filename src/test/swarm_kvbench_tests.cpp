// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvbench.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_kvbench_tests, BasicTestingSetup)

static modelnet::SwarmKvBench NotedBench()
{
    modelnet::SwarmKvBench bench;
    bench.bench_id = "bench-1";
    bench.measured = true;
    bench.want_publish = false;
    return bench;
}

BOOST_AUTO_TEST_CASE(empty_bench_is_bench)
{
    modelnet::SwarmKvBench bench = NotedBench();
    bench.bench_id.clear();
    std::string err = "prior";
    const modelnet::SwarmKvBenchResult result = modelnet::SwarmNoteKvBench(bench, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.tokens, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "BENCH");
    BOOST_CHECK_EQUAL(err, "BENCH");
}

BOOST_AUTO_TEST_CASE(unmeasured_without_publish_is_not_published)
{
    modelnet::SwarmKvBench bench = NotedBench();
    bench.measured = false;
    bench.want_publish = false;
    std::string err = "prior";
    const modelnet::SwarmKvBenchResult result = modelnet::SwarmNoteKvBench(bench, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.tokens, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "NOT_PUBLISHED");
    BOOST_CHECK_EQUAL(err, "NOT_PUBLISHED");
}

BOOST_AUTO_TEST_CASE(want_publish_when_measured_is_held)
{
    modelnet::SwarmKvBench bench = NotedBench();
    bench.want_publish = true;
    bench.measured = true;
    std::string err = "prior";
    const modelnet::SwarmKvBenchResult result = modelnet::SwarmNoteKvBench(bench, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.tokens, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(measured_without_publish_is_noted)
{
    modelnet::SwarmKvBench bench = NotedBench();
    bench.measured = true;
    bench.want_publish = false;
    std::string err = "prior";
    const modelnet::SwarmKvBenchResult result = modelnet::SwarmNoteKvBench(bench, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.tokens, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
