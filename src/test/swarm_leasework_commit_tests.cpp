// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_leasework/swarm_leasework.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_leasework_commit_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_task_is_task_and_empty_hash_stores_nothing)
{
    modelnet::SwarmLeaseWork plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Commit("missing", 1, "hash-a", err));
    BOOST_REQUIRE_EQUAL(err, "TASK");
    BOOST_REQUIRE(!plane.has("missing"));
    BOOST_REQUIRE(!plane.committed("missing"));

    BOOST_REQUIRE(!plane.Commit("missing", 9, "", err));
    BOOST_REQUIRE_EQUAL(err, "TASK");

    BOOST_REQUIRE(plane.Grant("task-1", "worker-a", 1000, 5000, err));
    BOOST_REQUIRE(!plane.commit_right());

    err = "prior";
    BOOST_REQUIRE(!plane.Commit("task-1", 1, "hash-a", err));
    BOOST_REQUIRE_EQUAL(err, "LEADER");
    BOOST_REQUIRE(!plane.committed("task-1"));
    BOOST_REQUIRE(plane.result_hash("task-1").empty());

    BOOST_REQUIRE(plane.ClaimLeader("worker-a", err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Commit("task-1", 1, "", err));
    BOOST_REQUIRE_EQUAL(err, "HASH");
    BOOST_REQUIRE(!plane.committed("task-1"));
    BOOST_REQUIRE(plane.result_hash("task-1").empty());

    BOOST_REQUIRE(plane.Commit("task-1", 1, "hash-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.committed("task-1"));
    BOOST_REQUIRE_EQUAL(plane.result_hash("task-1"), "hash-a");
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_CASE(the_same_hash_is_replay_and_a_different_hash_conflicts)
{
    modelnet::SwarmLeaseWork plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Grant("task-1", "worker-a", 1000, 5000, err));
    BOOST_REQUIRE(plane.Grant("task-2", "worker-a", 1000, 5000, err));
    BOOST_REQUIRE(plane.ClaimLeader("worker-a", err));

    BOOST_REQUIRE(plane.Commit("task-1", 1, "hash-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.result_hash("task-1"), "hash-a");

    err = "prior";
    BOOST_REQUIRE(!plane.Commit("task-1", 1, "hash-a", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.result_hash("task-1"), "hash-a");

    err = "prior";
    BOOST_REQUIRE(!plane.Commit("task-1", 1, "hash-b", err));
    BOOST_REQUIRE_EQUAL(err, "CONFLICT");
    BOOST_REQUIRE_EQUAL(plane.result_hash("task-1"), "hash-a");
    BOOST_REQUIRE(plane.committed("task-1"));

    err = "prior";
    BOOST_REQUIRE(!plane.Commit("task-1", 1, "hash-a", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.result_hash("task-1"), "hash-a");

    BOOST_REQUIRE(plane.Commit("task-2", 1, "hash-b", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.result_hash("task-2"), "hash-b");
    BOOST_REQUIRE_EQUAL(plane.result_hash("task-1"), "hash-a");

    plane.BumpEpoch();
    BOOST_REQUIRE(plane.ClaimLeader("worker-a", err));
    err = "prior";
    BOOST_REQUIRE(!plane.Commit("task-1", 2, "hash-b", err));
    BOOST_REQUIRE_EQUAL(err, "CONFLICT");
    BOOST_REQUIRE_EQUAL(plane.result_hash("task-1"), "hash-a");
    err = "prior";
    BOOST_REQUIRE(!plane.Commit("task-1", 2, "hash-a", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.result_hash("task-1"), "hash-a");
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_CASE(commit_without_a_grant_does_not_create_one)
{
    modelnet::SwarmLeaseWork plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Commit("task-1", 1, "", err));
    BOOST_REQUIRE_EQUAL(err, "TASK");
    BOOST_REQUIRE_EQUAL(plane.grants(), 0u);
    BOOST_REQUIRE_EQUAL(plane.epoch(), 1);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
