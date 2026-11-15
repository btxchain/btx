// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cpucap.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_cpucap_tests, BasicTestingSetup)

static modelnet::SwarmCpuCap NotedCap()
{
    modelnet::SwarmCpuCap cap;
    cap.node_id = "node-1";
    cap.requested_threads = 8;
    cap.want_launch = false;
    return cap;
}

static void ExpectNotLaunched(const modelnet::SwarmCpuCapResult& result)
{
    BOOST_CHECK(!result.launched);
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_cpu)
{
    modelnet::SwarmCpuCap cap = NotedCap();
    cap.node_id.clear();
    std::string err = "prior";
    const modelnet::SwarmCpuCapResult result = modelnet::SwarmNoteCpuCap(cap, err);
    ExpectNotLaunched(result);
    BOOST_CHECK_EQUAL(result.threads_used, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "CPU");
    BOOST_CHECK_EQUAL(err, "CPU");
}

BOOST_AUTO_TEST_CASE(empty_node_id_wins_over_cap_and_launch)
{
    modelnet::SwarmCpuCap cap = NotedCap();
    cap.node_id.clear();
    cap.requested_threads = 128;
    cap.want_launch = true;
    std::string err = "prior";
    const modelnet::SwarmCpuCapResult result = modelnet::SwarmNoteCpuCap(cap, err);
    ExpectNotLaunched(result);
    BOOST_CHECK_EQUAL(result.threads_used, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "CPU");
    BOOST_CHECK_EQUAL(err, "CPU");
}

BOOST_AUTO_TEST_CASE(requested_threads_below_one_is_cpu)
{
    modelnet::SwarmCpuCap cap = NotedCap();
    cap.requested_threads = 0;
    std::string err = "prior";
    const modelnet::SwarmCpuCapResult result = modelnet::SwarmNoteCpuCap(cap, err);
    ExpectNotLaunched(result);
    BOOST_CHECK_EQUAL(result.threads_used, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "CPU");
    BOOST_CHECK_EQUAL(err, "CPU");
}

BOOST_AUTO_TEST_CASE(negative_requested_threads_is_cpu)
{
    modelnet::SwarmCpuCap cap = NotedCap();
    cap.requested_threads = -1;
    std::string err = "prior";
    const modelnet::SwarmCpuCapResult result = modelnet::SwarmNoteCpuCap(cap, err);
    ExpectNotLaunched(result);
    BOOST_CHECK_EQUAL(result.threads_used, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "CPU");
    BOOST_CHECK_EQUAL(err, "CPU");
}

BOOST_AUTO_TEST_CASE(below_one_wins_over_want_launch)
{
    modelnet::SwarmCpuCap cap = NotedCap();
    cap.requested_threads = 0;
    cap.want_launch = true;
    std::string err = "prior";
    const modelnet::SwarmCpuCapResult result = modelnet::SwarmNoteCpuCap(cap, err);
    ExpectNotLaunched(result);
    BOOST_CHECK_EQUAL(result.threads_used, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "CPU");
    BOOST_CHECK_EQUAL(err, "CPU");
}

BOOST_AUTO_TEST_CASE(requested_threads_128_is_capped)
{
    modelnet::SwarmCpuCap cap = NotedCap();
    cap.requested_threads = 128;
    cap.want_launch = false;
    std::string err = "prior";
    const modelnet::SwarmCpuCapResult result = modelnet::SwarmNoteCpuCap(cap, err);
    ExpectNotLaunched(result);
    BOOST_CHECK_EQUAL(result.threads_used, static_cast<int64_t>(64));
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(capped_wins_when_want_launch)
{
    modelnet::SwarmCpuCap cap = NotedCap();
    cap.requested_threads = 128;
    cap.want_launch = true;
    std::string err = "prior";
    const modelnet::SwarmCpuCapResult result = modelnet::SwarmNoteCpuCap(cap, err);
    ExpectNotLaunched(result);
    BOOST_CHECK(cap.want_launch);
    BOOST_CHECK_EQUAL(result.threads_used, static_cast<int64_t>(64));
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(want_launch_with_eight_is_held)
{
    modelnet::SwarmCpuCap cap = NotedCap();
    cap.requested_threads = 8;
    cap.want_launch = true;
    std::string err = "prior";
    const modelnet::SwarmCpuCapResult result = modelnet::SwarmNoteCpuCap(cap, err);
    ExpectNotLaunched(result);
    BOOST_CHECK_EQUAL(result.threads_used, static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(eight_without_launch_is_noted)
{
    modelnet::SwarmCpuCap cap = NotedCap();
    cap.requested_threads = 8;
    cap.want_launch = false;
    std::string err = "prior";
    const modelnet::SwarmCpuCapResult result = modelnet::SwarmNoteCpuCap(cap, err);
    ExpectNotLaunched(result);
    BOOST_CHECK(!cap.want_launch);
    BOOST_CHECK_EQUAL(result.threads_used, static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
