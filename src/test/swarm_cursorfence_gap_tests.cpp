// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cursorfence/swarm_cursorfence.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_cursorfence_gap_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(next_past_cursor_plus_one_is_gap_and_the_cursor_stays)
{
    modelnet::SwarmCursorFence plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.cursor() == 0);

    BOOST_REQUIRE(!plane.Advance(2, err));
    BOOST_REQUIRE_EQUAL(err, "GAP");
    BOOST_REQUIRE(plane.cursor() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Advance(100, err));
    BOOST_REQUIRE_EQUAL(err, "GAP");
    BOOST_REQUIRE(plane.cursor() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Advance(std::numeric_limits<int64_t>::max(), err));
    BOOST_REQUIRE_EQUAL(err, "GAP");
    BOOST_REQUIRE(plane.cursor() == 0);
    BOOST_REQUIRE(!plane.committed(0));
    BOOST_REQUIRE(!plane.committed(2));
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);

    BOOST_REQUIRE(plane.Advance(1, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.cursor() == 1);

    err = "prior";
    BOOST_REQUIRE(!plane.Advance(3, err));
    BOOST_REQUIRE_EQUAL(err, "GAP");
    BOOST_REQUIRE(plane.cursor() == 1);

    err = "prior";
    BOOST_REQUIRE(!plane.Advance(std::numeric_limits<int64_t>::max(), err));
    BOOST_REQUIRE_EQUAL(err, "GAP");
    BOOST_REQUIRE(plane.cursor() == 1);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);

    BOOST_REQUIRE(plane.Advance(2, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.cursor() == 2);
}

BOOST_AUTO_TEST_CASE(commit_of_a_different_step_is_gap_and_stores_nothing)
{
    modelnet::SwarmCursorFence plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Commit(1, "hash-1", err));
    BOOST_REQUIRE_EQUAL(err, "GAP");
    BOOST_REQUIRE(plane.cursor() == 0);
    BOOST_REQUIRE(!plane.committed(1));
    BOOST_REQUIRE(plane.hash_at(1).empty());

    BOOST_REQUIRE(plane.Commit(0, "hash-0", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.hash_at(0), "hash-0");

    BOOST_REQUIRE(plane.Advance(1, err));
    BOOST_REQUIRE(plane.Advance(2, err));
    BOOST_REQUIRE(plane.cursor() == 2);

    err = "prior";
    BOOST_REQUIRE(!plane.Commit(0, "hash-0-again", err));
    BOOST_REQUIRE_EQUAL(err, "GAP");
    BOOST_REQUIRE_EQUAL(plane.hash_at(0), "hash-0");

    err = "prior";
    BOOST_REQUIRE(!plane.Commit(1, "hash-1", err));
    BOOST_REQUIRE_EQUAL(err, "GAP");
    BOOST_REQUIRE(!plane.committed(1));
    BOOST_REQUIRE(plane.hash_at(1).empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Commit(3, "hash-3", err));
    BOOST_REQUIRE_EQUAL(err, "GAP");
    BOOST_REQUIRE(!plane.committed(3));
    BOOST_REQUIRE(plane.cursor() == 2);
    BOOST_REQUIRE_EQUAL(plane.hash_at(0), "hash-0");
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);

    BOOST_REQUIRE(plane.Commit(2, "hash-2", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.hash_at(2), "hash-2");
    BOOST_REQUIRE_EQUAL(plane.hash_at(0), "hash-0");
}

BOOST_AUTO_TEST_SUITE_END()
