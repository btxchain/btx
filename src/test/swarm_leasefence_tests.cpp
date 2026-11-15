// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_leasefence.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_leasefence_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(grant_stores_a_lease_at_epoch_one)
{
    modelnet::SwarmLeaseFence fence;
    BOOST_CHECK_EQUAL(fence.epoch(), 1);
    std::string err = "prior";
    BOOST_REQUIRE(fence.Grant("worker-a", "job-1", 1, 5000, 1000, err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(fence.Commit("worker-a", "job-1", 1, 1000, "hash-a", err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(an_expired_grant_stores_nothing)
{
    modelnet::SwarmLeaseFence fence;
    std::string err = "prior";
    BOOST_CHECK(!fence.Grant("worker-a", "job-1", 1, 1000, 1000, err));
    BOOST_CHECK_EQUAL(err, "LEASE_EXPIRED");
    BOOST_CHECK(!fence.Grant("worker-a", "job-1", 1, 999, 1000, err));
    BOOST_CHECK_EQUAL(err, "LEASE_EXPIRED");
    BOOST_CHECK(!fence.Commit("worker-a", "job-1", 1, 1000, "hash-a", err));
    BOOST_CHECK_EQUAL(err, "JOB");

    BOOST_REQUIRE(fence.Grant("worker-a", "job-1", 1, 5000, 1000, err));
    BOOST_CHECK(!fence.Grant("worker-b", "job-1", 1, 1000, 2000, err));
    BOOST_CHECK_EQUAL(err, "LEASE_EXPIRED");
    BOOST_REQUIRE(fence.Commit("worker-a", "job-1", 1, 2000, "hash-a", err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(bump_makes_the_old_grant_stale)
{
    modelnet::SwarmLeaseFence fence;
    std::string err = "prior";
    BOOST_REQUIRE(fence.Grant("worker-a", "job-1", 1, 5000, 1000, err));
    fence.BumpEpoch();
    BOOST_CHECK_EQUAL(fence.epoch(), 2);

    BOOST_CHECK(!fence.Commit("worker-a", "job-1", 1, 1500, "hash-a", err));
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");
    BOOST_CHECK(!fence.Commit("worker-a", "job-1", 2, 1500, "hash-b", err));
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");

    BOOST_CHECK(!fence.Grant("worker-a", "job-2", 1, 5000, 1500, err));
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");
    BOOST_CHECK(!fence.Commit("worker-a", "job-2", 2, 1500, "hash-c", err));
    BOOST_CHECK_EQUAL(err, "JOB");

    BOOST_REQUIRE(fence.Grant("worker-a", "job-2", 2, 8000, 1500, err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(fence.Commit("worker-a", "job-2", 2, 1500, "hash-c", err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(the_same_result_commits_again)
{
    modelnet::SwarmLeaseFence fence;
    std::string err = "prior";
    BOOST_REQUIRE(fence.Grant("worker-a", "job-1", 1, 5000, 1000, err));
    BOOST_REQUIRE(fence.Commit("worker-a", "job-1", 1, 4000, "hash-a", err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(fence.Commit("worker-a", "job-1", 1, 4500, "hash-a", err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(fence.Commit("worker-a", "job-1", 1, 5000, "hash-a", err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(a_different_result_conflicts_and_keeps_the_first)
{
    modelnet::SwarmLeaseFence fence;
    std::string err = "prior";
    BOOST_REQUIRE(fence.Grant("worker-a", "job-1", 1, 5000, 1000, err));
    BOOST_REQUIRE(fence.Commit("worker-a", "job-1", 1, 2000, "hash-a", err));
    BOOST_CHECK(!fence.Commit("worker-a", "job-1", 1, 2000, "hash-b", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_REQUIRE(fence.Commit("worker-a", "job-1", 1, 2000, "hash-a", err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(empty_worker_or_job_is_job_and_a_live_second_grant_is_replay)
{
    modelnet::SwarmLeaseFence fence;
    std::string err = "prior";
    BOOST_CHECK(!fence.Grant("", "job-1", 1, 5000, 1000, err));
    BOOST_CHECK_EQUAL(err, "JOB");
    BOOST_CHECK(!fence.Grant("worker-a", "", 1, 5000, 1000, err));
    BOOST_CHECK_EQUAL(err, "JOB");
    BOOST_CHECK(!fence.Commit("worker-a", "job-1", 1, 1000, "hash-a", err));
    BOOST_CHECK_EQUAL(err, "JOB");

    BOOST_REQUIRE(fence.Grant("worker-a", "job-1", 1, 5000, 1000, err));
    BOOST_CHECK(!fence.Grant("worker-b", "job-1", 1, 9000, 2000, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!fence.Commit("worker-b", "job-1", 1, 2000, "hash-b", err));
    BOOST_CHECK_EQUAL(err, "WORKER");
    BOOST_REQUIRE(fence.Commit("worker-a", "job-1", 1, 2000, "hash-a", err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(an_empty_result_is_hash_and_a_late_commit_does_not_store)
{
    modelnet::SwarmLeaseFence fence;
    std::string err = "prior";
    BOOST_REQUIRE(fence.Grant("worker-a", "job-1", 1, 5000, 1000, err));
    BOOST_CHECK(!fence.Commit("worker-a", "job-1", 1, 5001, "hash-a", err));
    BOOST_CHECK_EQUAL(err, "LEASE_EXPIRED");
    BOOST_CHECK(!fence.Commit("worker-a", "job-1", 1, 5000, "", err));
    BOOST_CHECK_EQUAL(err, "HASH");
    BOOST_REQUIRE(fence.Commit("worker-a", "job-1", 1, 5000, "hash-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!fence.Commit("worker-a", "job-1", 1, 5000, "hash-b", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
}

BOOST_AUTO_TEST_SUITE_END()
