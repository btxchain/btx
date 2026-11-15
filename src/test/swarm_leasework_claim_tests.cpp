// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_leasework/swarm_leasework.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_leasework_claim_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(claim_requires_a_live_grant_and_the_first_leader_stays)
{
    modelnet::SwarmLeaseWork plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.ClaimLeader("", err));
    BOOST_REQUIRE_EQUAL(err, "TASK");
    BOOST_REQUIRE(plane.leader().empty());
    BOOST_REQUIRE(!plane.commit_right());

    err = "prior";
    BOOST_REQUIRE(!plane.ClaimLeader("worker-a", err));
    BOOST_REQUIRE_EQUAL(err, "TASK");
    BOOST_REQUIRE(!plane.commit_right());

    BOOST_REQUIRE(plane.Grant("task-1", "worker-a", 1000, 1000, err));
    BOOST_REQUIRE(plane.Grant("task-2", "worker-b", 1000, 5000, err));
    BOOST_REQUIRE(plane.live("worker-a"));
    BOOST_REQUIRE(plane.live("worker-b"));

    BOOST_REQUIRE(plane.ClaimLeader("worker-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.leader(), "worker-a");
    BOOST_REQUIRE(plane.commit_right());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.ClaimLeader("worker-a", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.leader(), "worker-a");

    err = "prior";
    BOOST_REQUIRE(!plane.ClaimLeader("worker-b", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.leader(), "worker-a");
    BOOST_REQUIRE(plane.commit_right());

    err = "prior";
    BOOST_REQUIRE(!plane.ClaimLeader("", err));
    BOOST_REQUIRE_EQUAL(err, "TASK");
    BOOST_REQUIRE_EQUAL(plane.leader(), "worker-a");

    BOOST_REQUIRE(plane.Commit("task-1", 1, "hash-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.result_hash("task-1"), "hash-a");
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_CASE(after_bump_only_a_live_grant_can_reclaim)
{
    modelnet::SwarmLeaseWork plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Grant("task-1", "worker-a", 1000, 5000, err));
    BOOST_REQUIRE(plane.ClaimLeader("worker-a", err));
    plane.BumpEpoch();
    BOOST_REQUIRE_EQUAL(plane.epoch(), 2);
    BOOST_REQUIRE(plane.leader().empty());
    BOOST_REQUIRE(!plane.commit_right());

    err = "prior";
    BOOST_REQUIRE(!plane.Commit("task-1", 2, "hash-a", err));
    BOOST_REQUIRE_EQUAL(err, "LEADER");
    BOOST_REQUIRE(!plane.committed("task-1"));

    err = "prior";
    BOOST_REQUIRE(!plane.ClaimLeader("worker-z", err));
    BOOST_REQUIRE_EQUAL(err, "TASK");
    BOOST_REQUIRE(!plane.commit_right());

    BOOST_REQUIRE(plane.ClaimLeader("worker-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.leader(), "worker-a");
    BOOST_REQUIRE(plane.commit_right());
    BOOST_REQUIRE(plane.Commit("task-1", 2, "hash-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.result_hash("task-1"), "hash-a");
    BOOST_REQUIRE_EQUAL(plane.worker("task-1"), "worker-a");
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_SUITE_END()
