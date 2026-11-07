// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_leaderepoch.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_leaderepoch_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(claim_sets_the_leader_at_epoch_one)
{
    modelnet::SwarmLeaderEpoch book;
    BOOST_CHECK_EQUAL(book.epoch(), 1);
    BOOST_CHECK(book.Leader().empty());

    std::string err = "prior";
    BOOST_CHECK(!book.Claim("", 1, err));
    BOOST_CHECK_EQUAL(err, "LEADER");
    BOOST_CHECK(book.Leader().empty());
    BOOST_CHECK_EQUAL(book.epoch(), 1);

    BOOST_CHECK(!book.Claim("alice", 0, err));
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");
    BOOST_CHECK(book.Leader().empty());

    BOOST_CHECK(!book.Claim("alice", 2, err));
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");
    BOOST_CHECK(book.Leader().empty());

    BOOST_REQUIRE(book.Claim("alice", 1, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.Leader(), "alice");
    BOOST_CHECK_EQUAL(book.epoch(), 1);

    BOOST_REQUIRE(book.Assign("alice", 1, "task-a", err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(!book.Assign("alice", 1, "", err));
    BOOST_CHECK_EQUAL(err, "TASK");

    BOOST_CHECK(!book.Assign("alice", 1, "task-a", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");

    BOOST_CHECK(!book.Assign("bob", 1, "task-b", err));
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");

    BOOST_REQUIRE(book.Assign("alice", 1, "task-b", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.Leader(), "alice");
}

BOOST_AUTO_TEST_CASE(bump_invalidates_the_old_leader)
{
    modelnet::SwarmLeaderEpoch book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Claim("alice", 1, err));
    BOOST_REQUIRE(book.Assign("alice", 1, "task-a", err));

    book.Bump();
    BOOST_CHECK_EQUAL(book.epoch(), 2);
    BOOST_CHECK(book.Leader().empty());

    BOOST_CHECK(!book.Assign("alice", 1, "task-b", err));
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");
    BOOST_CHECK(!book.Assign("alice", 2, "task-b", err));
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");
    BOOST_CHECK(!book.Claim("alice", 1, err));
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");
    BOOST_CHECK(book.Leader().empty());
    BOOST_CHECK_EQUAL(book.epoch(), 2);

    BOOST_CHECK(!book.Claim("", 2, err));
    BOOST_CHECK_EQUAL(err, "LEADER");
    BOOST_CHECK(book.Leader().empty());
}

BOOST_AUTO_TEST_CASE(a_new_claim_can_assign)
{
    modelnet::SwarmLeaderEpoch book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Claim("alice", 1, err));
    BOOST_REQUIRE(book.Assign("alice", 1, "task-a", err));
    book.Bump();

    BOOST_REQUIRE(book.Claim("bob", 2, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.Leader(), "bob");
    BOOST_CHECK_EQUAL(book.epoch(), 2);

    BOOST_CHECK(!book.Assign("alice", 2, "task-c", err));
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");

    BOOST_REQUIRE(book.Assign("bob", 2, "task-c", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.Leader(), "bob");

    BOOST_CHECK(!book.Assign("bob", 2, "task-a", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(book.Assign("bob", 2, "task-d", err));
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(a_stale_epoch_cannot_claim_or_assign)
{
    modelnet::SwarmLeaderEpoch book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Claim("alice", 1, err));
    book.Bump();
    BOOST_REQUIRE(book.Claim("bob", 2, err));

    BOOST_CHECK(!book.Claim("carol", 1, err));
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");
    BOOST_CHECK_EQUAL(book.Leader(), "bob");
    BOOST_CHECK_EQUAL(book.epoch(), 2);

    BOOST_CHECK(!book.Assign("bob", 1, "task-e", err));
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");
    BOOST_CHECK(!book.Assign("alice", 1, "task-e", err));
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");

    BOOST_REQUIRE(book.Assign("bob", 2, "task-e", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.Leader(), "bob");
    BOOST_CHECK_EQUAL(book.epoch(), 2);
}

BOOST_AUTO_TEST_SUITE_END()
