// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_conflict.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_conflict_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_task_worker_or_hash_is_task)
{
    modelnet::SwarmConflict conflict;
    std::string err = "prior";
    BOOST_CHECK(!conflict.Offer("", "worker-a", "hash-a", err));
    BOOST_CHECK_EQUAL(err, "TASK");
    BOOST_CHECK(conflict.Hash("").empty());
    BOOST_CHECK(!conflict.conflicted(""));

    err = "prior";
    BOOST_CHECK(!conflict.Offer("task-1", "", "hash-a", err));
    BOOST_CHECK_EQUAL(err, "TASK");
    BOOST_CHECK(conflict.Hash("task-1").empty());
    BOOST_CHECK(!conflict.conflicted("task-1"));

    err = "prior";
    BOOST_CHECK(!conflict.Offer("task-1", "worker-a", "", err));
    BOOST_CHECK_EQUAL(err, "TASK");
    BOOST_CHECK(conflict.Hash("task-1").empty());
    BOOST_CHECK(!conflict.conflicted("task-1"));

    err = "prior";
    BOOST_CHECK(!conflict.Offer("", "", "", err));
    BOOST_CHECK_EQUAL(err, "TASK");
}

BOOST_AUTO_TEST_CASE(first_offer_stores_and_same_worker_same_hash_again)
{
    modelnet::SwarmConflict conflict;
    std::string err = "prior";
    BOOST_CHECK(conflict.Hash("task-1").empty());
    BOOST_CHECK(!conflict.conflicted("task-1"));

    BOOST_REQUIRE(conflict.Offer("task-1", "worker-a", "hash-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(conflict.Hash("task-1"), "hash-a");
    BOOST_CHECK(!conflict.conflicted("task-1"));

    err = "prior";
    BOOST_REQUIRE(conflict.Offer("task-1", "worker-a", "hash-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(conflict.Hash("task-1"), "hash-a");
    BOOST_CHECK(!conflict.conflicted("task-1"));
}

BOOST_AUTO_TEST_CASE(different_hash_is_conflict_and_keeps_the_first)
{
    modelnet::SwarmConflict conflict;
    std::string err = "prior";
    BOOST_REQUIRE(conflict.Offer("task-1", "worker-a", "hash-a", err));
    BOOST_CHECK(err.empty());

    err = "prior";
    BOOST_CHECK(!conflict.Offer("task-1", "worker-a", "hash-b", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK_EQUAL(conflict.Hash("task-1"), "hash-a");
    BOOST_CHECK(conflict.conflicted("task-1"));
    BOOST_CHECK(conflict.Hash("task-1").find("hash-b") == std::string::npos);

    err = "prior";
    BOOST_CHECK(!conflict.Offer("task-1", "worker-b", "hash-c", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK_EQUAL(conflict.Hash("task-1"), "hash-a");
    BOOST_CHECK(conflict.conflicted("task-1"));

    err = "prior";
    BOOST_REQUIRE(conflict.Offer("task-1", "worker-a", "hash-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(conflict.Hash("task-1"), "hash-a");
    BOOST_CHECK(conflict.conflicted("task-1"));

    err = "prior";
    BOOST_CHECK(!conflict.Offer("task-1", "worker-a", "", err));
    BOOST_CHECK_EQUAL(err, "TASK");
    BOOST_CHECK_EQUAL(conflict.Hash("task-1"), "hash-a");
    BOOST_CHECK(conflict.conflicted("task-1"));
}

BOOST_AUTO_TEST_CASE(same_hash_from_another_worker_is_not_a_conflict)
{
    modelnet::SwarmConflict conflict;
    std::string err = "prior";
    BOOST_REQUIRE(conflict.Offer("task-1", "worker-a", "hash-a", err));
    BOOST_REQUIRE(conflict.Offer("task-1", "worker-b", "hash-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(conflict.Hash("task-1"), "hash-a");
    BOOST_CHECK(!conflict.conflicted("task-1"));
}

BOOST_AUTO_TEST_CASE(unknown_task_is_empty_and_tasks_are_independent)
{
    modelnet::SwarmConflict conflict;
    BOOST_CHECK(conflict.Hash("missing").empty());
    BOOST_CHECK(!conflict.conflicted("missing"));

    std::string err = "prior";
    BOOST_REQUIRE(conflict.Offer("task-a", "worker-a", "hash-a", err));
    BOOST_REQUIRE(conflict.Offer("task-b", "worker-b", "hash-b", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(conflict.Hash("task-a"), "hash-a");
    BOOST_CHECK_EQUAL(conflict.Hash("task-b"), "hash-b");
    BOOST_CHECK(!conflict.conflicted("task-a"));
    BOOST_CHECK(!conflict.conflicted("task-b"));

    err = "prior";
    BOOST_CHECK(!conflict.Offer("task-a", "worker-a", "hash-other", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK(conflict.conflicted("task-a"));
    BOOST_CHECK(!conflict.conflicted("task-b"));
    BOOST_CHECK_EQUAL(conflict.Hash("task-a"), "hash-a");
    BOOST_CHECK_EQUAL(conflict.Hash("task-b"), "hash-b");
    BOOST_CHECK(conflict.Hash("task-c").empty());
    BOOST_CHECK(!conflict.conflicted("task-c"));
}

BOOST_AUTO_TEST_SUITE_END()
