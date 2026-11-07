// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cursorfence/swarm_cursorfence.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_cursorfence_advance_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(exact_plus_one_sets_the_cursor)
{
    modelnet::SwarmCursorFence plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.cursor() == 0);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);

    BOOST_REQUIRE(plane.Advance(1, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.cursor() == 1);

    BOOST_REQUIRE(plane.Advance(2, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.cursor() == 2);

    BOOST_REQUIRE(plane.Advance(3, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.cursor() == 3);

    BOOST_REQUIRE(plane.Advance(4, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.cursor() == 4);

    BOOST_REQUIRE(plane.Advance(5, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.cursor() == 5);
    BOOST_REQUIRE(!plane.committed(5));
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);
}

BOOST_AUTO_TEST_CASE(a_refused_advance_still_allows_the_next_exact_step)
{
    modelnet::SwarmCursorFence plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Advance(-4, err));
    BOOST_REQUIRE_EQUAL(err, "RANGE");
    BOOST_REQUIRE(!plane.Advance(0, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE(!plane.Advance(2, err));
    BOOST_REQUIRE_EQUAL(err, "GAP");
    BOOST_REQUIRE(plane.cursor() == 0);

    BOOST_REQUIRE(plane.Advance(1, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.cursor() == 1);

    BOOST_REQUIRE(!plane.Advance(1, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE(!plane.Advance(3, err));
    BOOST_REQUIRE_EQUAL(err, "GAP");
    BOOST_REQUIRE(plane.cursor() == 1);

    BOOST_REQUIRE(plane.Advance(2, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.cursor() == 2);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);
}

BOOST_AUTO_TEST_CASE(advance_does_not_store_a_hash_or_mine)
{
    modelnet::SwarmCursorFence plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Advance(1, err));
    BOOST_REQUIRE(!plane.committed(0));
    BOOST_REQUIRE(!plane.committed(1));
    BOOST_REQUIRE(plane.hash_at(0).empty());
    BOOST_REQUIRE(plane.hash_at(1).empty());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);

    BOOST_REQUIRE(plane.Commit(1, "hash-1", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.hash_at(1), "hash-1");

    BOOST_REQUIRE(plane.Advance(2, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.cursor() == 2);
    BOOST_REQUIRE_EQUAL(plane.hash_at(1), "hash-1");
    BOOST_REQUIRE(!plane.committed(2));
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
