// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cursorfence/swarm_cursorfence.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_cursorfence_commit_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_hash_is_hash_and_stores_nothing)
{
    modelnet::SwarmCursorFence plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Commit(0, "", err));
    BOOST_REQUIRE_EQUAL(err, "HASH");
    BOOST_REQUIRE(plane.cursor() == 0);
    BOOST_REQUIRE(!plane.committed(0));
    BOOST_REQUIRE(plane.hash_at(0).empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Commit(1, "", err));
    BOOST_REQUIRE_EQUAL(err, "HASH");
    BOOST_REQUIRE(!plane.committed(1));
    BOOST_REQUIRE(plane.cursor() == 0);

    BOOST_REQUIRE(plane.Commit(0, "hash-0", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.hash_at(0), "hash-0");

    err = "prior";
    BOOST_REQUIRE(!plane.Commit(0, "", err));
    BOOST_REQUIRE_EQUAL(err, "HASH");
    BOOST_REQUIRE(plane.committed(0));
    BOOST_REQUIRE_EQUAL(plane.hash_at(0), "hash-0");
    BOOST_REQUIRE(plane.cursor() == 0);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);
}

BOOST_AUTO_TEST_CASE(first_hash_wins_same_hash_is_replay_different_hash_conflicts)
{
    modelnet::SwarmCursorFence plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Commit(0, "hash-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.committed(0));
    BOOST_REQUIRE_EQUAL(plane.hash_at(0), "hash-a");

    err = "prior";
    BOOST_REQUIRE(!plane.Commit(0, "hash-a", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.hash_at(0), "hash-a");

    err = "prior";
    BOOST_REQUIRE(!plane.Commit(0, "hash-b", err));
    BOOST_REQUIRE_EQUAL(err, "CONFLICT");
    BOOST_REQUIRE_EQUAL(plane.hash_at(0), "hash-a");
    BOOST_REQUIRE(plane.committed(0));

    err = "prior";
    BOOST_REQUIRE(!plane.Commit(0, "hash-a", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.hash_at(0), "hash-a");
    BOOST_REQUIRE(plane.cursor() == 0);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);

    BOOST_REQUIRE(plane.Advance(1, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.cursor() == 1);

    BOOST_REQUIRE(plane.Commit(1, "hash-b", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.hash_at(1), "hash-b");
    BOOST_REQUIRE_EQUAL(plane.hash_at(0), "hash-a");

    err = "prior";
    BOOST_REQUIRE(!plane.Commit(1, "hash-c", err));
    BOOST_REQUIRE_EQUAL(err, "CONFLICT");
    BOOST_REQUIRE_EQUAL(plane.hash_at(1), "hash-b");
    BOOST_REQUIRE_EQUAL(plane.hash_at(0), "hash-a");

    err = "prior";
    BOOST_REQUIRE(!plane.Commit(1, "hash-b", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.hash_at(1), "hash-b");

    err = "prior";
    BOOST_REQUIRE(!plane.Commit(0, "hash-z", err));
    BOOST_REQUIRE_EQUAL(err, "GAP");
    BOOST_REQUIRE_EQUAL(plane.hash_at(0), "hash-a");
    BOOST_REQUIRE(plane.cursor() == 1);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);
}

BOOST_AUTO_TEST_CASE(a_space_hash_is_stored_and_bytes_stay_distinct)
{
    modelnet::SwarmCursorFence plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Commit(0, " ", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.hash_at(0), " ");

    err = "prior";
    BOOST_REQUIRE(!plane.Commit(0, "  ", err));
    BOOST_REQUIRE_EQUAL(err, "CONFLICT");
    BOOST_REQUIRE_EQUAL(plane.hash_at(0), " ");

    const std::string binary("a\0b", 3);
    BOOST_REQUIRE(plane.Advance(1, err));
    BOOST_REQUIRE(plane.Commit(1, binary, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.hash_at(1) == binary);

    err = "prior";
    BOOST_REQUIRE(!plane.Commit(1, std::string("a\0c", 3), err));
    BOOST_REQUIRE_EQUAL(err, "CONFLICT");
    BOOST_REQUIRE(plane.hash_at(1) == binary);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
