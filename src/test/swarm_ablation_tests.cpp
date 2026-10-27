// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ablation.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_ablation_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_bench_is_bench)
{
    modelnet::SwarmAblation bench;
    bench.bench_id = "";
    bench.want_publish = false;
    std::string err;
    const modelnet::SwarmAblationResult result = modelnet::SwarmNoteAblation(bench, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "BENCH");
    BOOST_CHECK_EQUAL(err, "BENCH");
}

BOOST_AUTO_TEST_CASE(want_publish_is_held)
{
    modelnet::SwarmAblation bench;
    bench.bench_id = "bench";
    bench.want_publish = true;
    std::string err;
    const modelnet::SwarmAblationResult result = modelnet::SwarmNoteAblation(bench, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted_clears_err)
{
    modelnet::SwarmAblation bench;
    bench.bench_id = "bench";
    bench.want_publish = false;
    std::string err = "stale";
    const modelnet::SwarmAblationResult result = modelnet::SwarmNoteAblation(bench, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
