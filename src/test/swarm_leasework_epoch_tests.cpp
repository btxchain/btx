// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_leasework/swarm_leasework.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_leasework_epoch_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bump_keeps_the_grant_and_clears_the_commit_right)
{
    modelnet::SwarmLeaseWork plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Grant("task-1", "worker-a", 1000, 5000, err));
    BOOST_REQUIRE(plane.ClaimLeader("worker-a", err));
    BOOST_REQUIRE(plane.commit_right());
    BOOST_REQUIRE_EQUAL(plane.leader(), "worker-a");
    BOOST_REQUIRE(plane.Commit("task-1", 1, "hash-a", err));
    BOOST_REQUIRE(err.empty());

    plane.BumpEpoch();
    BOOST_REQUIRE_EQUAL(plane.epoch(), 2);
    BOOST_REQUIRE(plane.leader().empty());
    BOOST_REQUIRE(!plane.commit_right());
    BOOST_REQUIRE(plane.has("task-1"));
    BOOST_REQUIRE_EQUAL(plane.worker("task-1"), "worker-a");
    BOOST_REQUIRE_EQUAL(plane.grant_epoch("task-1"), 1);
    BOOST_REQUIRE(plane.committed("task-1"));
    BOOST_REQUIRE_EQUAL(plane.result_hash("task-1"), "hash-a");
    BOOST_REQUIRE(plane.live("worker-a"));
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.broadcast());

    err = "prior";
    BOOST_REQUIRE(!plane.Grant("task-1", "worker-b", 1500, 9000, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.worker("task-1"), "worker-a");
    BOOST_REQUIRE_EQUAL(plane.grant_epoch("task-1"), 1);
    BOOST_REQUIRE_EQUAL(plane.grants(), 1u);

    BOOST_REQUIRE(plane.Grant("task-2", "worker-b", 1500, 9000, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.grant_epoch("task-2"), 2);
    BOOST_REQUIRE_EQUAL(plane.epoch(), 2);
}

BOOST_AUTO_TEST_CASE(a_stale_epoch_does_not_store_the_hash)
{
    modelnet::SwarmLeaseWork plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Grant("task-1", "worker-a", 1000, 5000, err));
    BOOST_REQUIRE(plane.ClaimLeader("worker-a", err));
    plane.BumpEpoch();
    BOOST_REQUIRE_EQUAL(plane.epoch(), 2);
    BOOST_REQUIRE(!plane.commit_right());

    err = "prior";
    BOOST_REQUIRE(!plane.Commit("task-1", 1, "hash-a", err));
    BOOST_REQUIRE_EQUAL(err, "STALE_EPOCH");
    BOOST_REQUIRE(!plane.committed("task-1"));
    BOOST_REQUIRE(plane.result_hash("task-1").empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Commit("task-1", 1, "", err));
    BOOST_REQUIRE_EQUAL(err, "STALE_EPOCH");
    BOOST_REQUIRE(!plane.committed("task-1"));

    err = "prior";
    BOOST_REQUIRE(!plane.Commit("task-1", 2, "hash-a", err));
    BOOST_REQUIRE_EQUAL(err, "LEADER");
    BOOST_REQUIRE(!plane.committed("task-1"));

    BOOST_REQUIRE(plane.ClaimLeader("worker-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.commit_right());
    BOOST_REQUIRE_EQUAL(plane.leader(), "worker-a");

    BOOST_REQUIRE(plane.Commit("task-1", 2, "hash-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.committed("task-1"));
    BOOST_REQUIRE_EQUAL(plane.result_hash("task-1"), "hash-a");

    err = "prior";
    BOOST_REQUIRE(!plane.Commit("task-1", 1, "hash-b", err));
    BOOST_REQUIRE_EQUAL(err, "STALE_EPOCH");
    BOOST_REQUIRE_EQUAL(plane.result_hash("task-1"), "hash-a");
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(a_second_bump_clears_the_new_leader)
{
    modelnet::SwarmLeaseWork plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Grant("task-1", "worker-a", 1000, 8000, err));
    plane.BumpEpoch();
    BOOST_REQUIRE(plane.ClaimLeader("worker-a", err));
    BOOST_REQUIRE_EQUAL(plane.epoch(), 2);
    BOOST_REQUIRE(plane.commit_right());

    plane.BumpEpoch();
    BOOST_REQUIRE_EQUAL(plane.epoch(), 3);
    BOOST_REQUIRE(plane.leader().empty());
    BOOST_REQUIRE(!plane.commit_right());
    BOOST_REQUIRE_EQUAL(plane.worker("task-1"), "worker-a");

    err = "prior";
    BOOST_REQUIRE(!plane.Commit("task-1", 2, "hash-a", err));
    BOOST_REQUIRE_EQUAL(err, "STALE_EPOCH");
    BOOST_REQUIRE(!plane.committed("task-1"));

    err = "prior";
    BOOST_REQUIRE(!plane.Commit("task-1", 3, "hash-a", err));
    BOOST_REQUIRE_EQUAL(err, "LEADER");
    BOOST_REQUIRE(!plane.committed("task-1"));

    BOOST_REQUIRE(plane.ClaimLeader("worker-a", err));
    BOOST_REQUIRE(plane.Commit("task-1", 3, "hash-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.result_hash("task-1"), "hash-a");
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_SUITE_END()
