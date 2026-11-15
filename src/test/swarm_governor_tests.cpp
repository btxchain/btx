// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_governor.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_governor_tests, BasicTestingSetup)

static modelnet::SwarmGovernor NotedGovernor()
{
    modelnet::SwarmGovernor governor;
    governor.node_id = "node-1";
    governor.idle_off = false;
    governor.battery = false;
    governor.thermal = false;
    governor.metered = false;
    governor.requested_workers = 0;
    return governor;
}

static void ExpectWorkersStopped(const modelnet::SwarmGovernorResult& result)
{
    BOOST_CHECK_EQUAL(result.workers_running, static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_governor)
{
    modelnet::SwarmGovernor governor = NotedGovernor();
    governor.node_id.clear();
    std::string err = "prior";
    const modelnet::SwarmGovernorResult result = modelnet::SwarmNoteGovernor(governor, err);
    ExpectWorkersStopped(result);
    BOOST_CHECK_EQUAL(result.code, "GOVERNOR");
    BOOST_CHECK_EQUAL(err, "GOVERNOR");
}

BOOST_AUTO_TEST_CASE(empty_node_id_wins_over_drain_and_held)
{
    modelnet::SwarmGovernor governor = NotedGovernor();
    governor.node_id.clear();
    governor.battery = true;
    governor.requested_workers = 4;
    std::string err = "prior";
    const modelnet::SwarmGovernorResult result = modelnet::SwarmNoteGovernor(governor, err);
    ExpectWorkersStopped(result);
    BOOST_CHECK_EQUAL(result.code, "GOVERNOR");
    BOOST_CHECK_EQUAL(err, "GOVERNOR");
}

BOOST_AUTO_TEST_CASE(negative_requested_workers_is_governor)
{
    modelnet::SwarmGovernor governor = NotedGovernor();
    governor.requested_workers = -1;
    std::string err = "prior";
    const modelnet::SwarmGovernorResult result = modelnet::SwarmNoteGovernor(governor, err);
    ExpectWorkersStopped(result);
    BOOST_CHECK_EQUAL(result.code, "GOVERNOR");
    BOOST_CHECK_EQUAL(err, "GOVERNOR");
}

BOOST_AUTO_TEST_CASE(negative_requested_workers_wins_over_drain)
{
    modelnet::SwarmGovernor governor = NotedGovernor();
    governor.requested_workers = -1;
    governor.battery = true;
    std::string err = "prior";
    const modelnet::SwarmGovernorResult result = modelnet::SwarmNoteGovernor(governor, err);
    ExpectWorkersStopped(result);
    BOOST_CHECK_EQUAL(result.code, "GOVERNOR");
    BOOST_CHECK_EQUAL(err, "GOVERNOR");
}

BOOST_AUTO_TEST_CASE(battery_only_is_drain)
{
    modelnet::SwarmGovernor governor = NotedGovernor();
    governor.battery = true;
    std::string err = "prior";
    const modelnet::SwarmGovernorResult result = modelnet::SwarmNoteGovernor(governor, err);
    ExpectWorkersStopped(result);
    BOOST_CHECK(!governor.idle_off);
    BOOST_CHECK(governor.battery);
    BOOST_CHECK(!governor.thermal);
    BOOST_CHECK(!governor.metered);
    BOOST_CHECK_EQUAL(governor.requested_workers, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.code, "DRAIN");
    BOOST_CHECK_EQUAL(err, "DRAIN");
}

BOOST_AUTO_TEST_CASE(battery_wins_over_requested_workers)
{
    modelnet::SwarmGovernor governor = NotedGovernor();
    governor.battery = true;
    governor.requested_workers = 3;
    std::string err = "prior";
    const modelnet::SwarmGovernorResult result = modelnet::SwarmNoteGovernor(governor, err);
    ExpectWorkersStopped(result);
    BOOST_CHECK_EQUAL(result.code, "DRAIN");
    BOOST_CHECK_EQUAL(err, "DRAIN");
}

BOOST_AUTO_TEST_CASE(requested_workers_above_zero_is_held)
{
    modelnet::SwarmGovernor governor = NotedGovernor();
    governor.requested_workers = 2;
    std::string err = "prior";
    const modelnet::SwarmGovernorResult result = modelnet::SwarmNoteGovernor(governor, err);
    ExpectWorkersStopped(result);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(zero_requested_workers_is_noted)
{
    modelnet::SwarmGovernor governor = NotedGovernor();
    governor.requested_workers = 0;
    governor.idle_off = false;
    governor.battery = false;
    governor.thermal = false;
    governor.metered = false;
    std::string err = "prior";
    const modelnet::SwarmGovernorResult result = modelnet::SwarmNoteGovernor(governor, err);
    ExpectWorkersStopped(result);
    BOOST_CHECK_EQUAL(governor.requested_workers, static_cast<int64_t>(0));
    BOOST_CHECK(!governor.idle_off);
    BOOST_CHECK(!governor.battery);
    BOOST_CHECK(!governor.thermal);
    BOOST_CHECK(!governor.metered);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
