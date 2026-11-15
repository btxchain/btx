// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_trajectory.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_trajectory_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(enqueue_before_bind_is_policy)
{
    modelnet::SwarmTrajectoryQueue queue;
    std::string err;
    modelnet::SwarmTrajectoryItem item;
    item.example_id = "ex1";
    item.origin = "synthetic_trajectory";
    item.source_evidence = "evidence";
    BOOST_CHECK(!queue.Enqueue(item, err));
    BOOST_CHECK_EQUAL(err, "POLICY");
    BOOST_CHECK_EQUAL(queue.Size(), 0U);
}

BOOST_AUTO_TEST_CASE(empty_bind_is_policy)
{
    modelnet::SwarmTrajectoryQueue queue;
    std::string err = "prior";
    BOOST_CHECK(!queue.BindPolicy("", err));
    BOOST_CHECK_EQUAL(err, "POLICY");
    BOOST_CHECK(queue.Policy().empty());
}

BOOST_AUTO_TEST_CASE(a_second_policy_version_is_stale)
{
    modelnet::SwarmTrajectoryQueue queue;
    std::string err;
    BOOST_REQUIRE(queue.BindPolicy("v1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!queue.BindPolicy("v2", err));
    BOOST_CHECK_EQUAL(err, "STALE_POLICY");
    BOOST_CHECK_EQUAL(queue.Policy(), "v1");
    BOOST_CHECK(queue.BindPolicy("v1", err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(credential_origin_is_refused)
{
    modelnet::SwarmTrajectoryQueue queue;
    std::string err;
    BOOST_REQUIRE(queue.BindPolicy("v1", err));
    modelnet::SwarmTrajectoryItem item;
    item.example_id = "ex1";
    item.origin = "credential";
    item.source_evidence = "secret";
    BOOST_CHECK(!queue.Enqueue(item, err));
    BOOST_CHECK_EQUAL(err, "CREDENTIAL");
    BOOST_CHECK_EQUAL(queue.Size(), 0U);
}

BOOST_AUTO_TEST_CASE(private_conversation_without_rights_is_private_data)
{
    modelnet::SwarmTrajectoryQueue queue;
    std::string err;
    BOOST_REQUIRE(queue.BindPolicy("v1", err));
    modelnet::SwarmTrajectoryItem item;
    item.example_id = "ex1";
    item.origin = "private_conversation";
    item.rights_authorized = false;
    item.source_evidence = "";
    BOOST_CHECK(!queue.Enqueue(item, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(queue.Size(), 0U);
}

BOOST_AUTO_TEST_CASE(synthetic_trajectory_dequeues_unlearned)
{
    modelnet::SwarmTrajectoryQueue queue;
    std::string err;
    BOOST_REQUIRE(queue.BindPolicy("v1", err));
    modelnet::SwarmTrajectoryItem item;
    item.example_id = "ex1";
    item.origin = "synthetic_trajectory";
    item.source_evidence = "lab-note";
    BOOST_CHECK(queue.Enqueue(item, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(queue.Size(), 1U);

    modelnet::SwarmTrajectoryRow row;
    BOOST_CHECK(queue.Dequeue(row, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(row.item.example_id, "ex1");
    BOOST_CHECK(!row.learned);
    BOOST_CHECK(!row.policy_updated);
    BOOST_CHECK(!row.bytes_moved);
    BOOST_CHECK_EQUAL(queue.Size(), 0U);
    BOOST_CHECK_EQUAL(queue.Policy(), "v1");
}

BOOST_AUTO_TEST_CASE(second_enqueue_of_the_same_example_is_replay)
{
    modelnet::SwarmTrajectoryQueue queue;
    std::string err;
    BOOST_REQUIRE(queue.BindPolicy("v1", err));
    modelnet::SwarmTrajectoryItem item;
    item.example_id = "ex1";
    item.origin = "synthetic_trajectory";
    item.source_evidence = "lab-note";
    BOOST_REQUIRE(queue.Enqueue(item, err));
    BOOST_CHECK(!queue.Enqueue(item, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(queue.Size(), 1U);
}

BOOST_AUTO_TEST_SUITE_END()
