// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cursorfence/swarm_cursorfence.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_cursorfence_stale_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cursor_starts_at_zero_and_equal_next_is_stale)
{
    modelnet::SwarmCursorFence plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.cursor() == 0);
    BOOST_REQUIRE(!plane.committed(0));
    BOOST_REQUIRE(plane.hash_at(0).empty());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);

    BOOST_REQUIRE(!plane.Advance(0, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE(plane.cursor() == 0);
    BOOST_REQUIRE(!plane.committed(0));
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);
}

BOOST_AUTO_TEST_CASE(next_below_cursor_is_stale_and_the_cursor_stays)
{
    modelnet::SwarmCursorFence plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Advance(1, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.Advance(2, err));
    BOOST_REQUIRE(plane.Advance(3, err));
    BOOST_REQUIRE(plane.cursor() == 3);
    BOOST_REQUIRE(plane.Commit(3, "hash-3", err));
    BOOST_REQUIRE_EQUAL(plane.hash_at(3), "hash-3");

    err = "prior";
    BOOST_REQUIRE(!plane.Advance(3, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE(plane.cursor() == 3);

    err = "prior";
    BOOST_REQUIRE(!plane.Advance(2, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE(plane.cursor() == 3);

    err = "prior";
    BOOST_REQUIRE(!plane.Advance(1, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE(plane.cursor() == 3);

    err = "prior";
    BOOST_REQUIRE(!plane.Advance(0, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE(plane.cursor() == 3);
    BOOST_REQUIRE(plane.committed(3));
    BOOST_REQUIRE_EQUAL(plane.hash_at(3), "hash-3");
    BOOST_REQUIRE(!plane.committed(2));
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);

    BOOST_REQUIRE(plane.Advance(4, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.cursor() == 4);
    BOOST_REQUIRE_EQUAL(plane.hash_at(3), "hash-3");
}

BOOST_AUTO_TEST_CASE(negative_next_is_range_and_does_not_count_as_stale)
{
    modelnet::SwarmCursorFence plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Advance(-1, err));
    BOOST_REQUIRE_EQUAL(err, "RANGE");
    BOOST_REQUIRE(plane.cursor() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Advance(std::numeric_limits<int64_t>::min(), err));
    BOOST_REQUIRE_EQUAL(err, "RANGE");
    BOOST_REQUIRE(plane.cursor() == 0);
    BOOST_REQUIRE(!plane.committed(0));
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);

    BOOST_REQUIRE(plane.Advance(1, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.cursor() == 1);

    err = "prior";
    BOOST_REQUIRE(!plane.Advance(-1, err));
    BOOST_REQUIRE_EQUAL(err, "RANGE");
    BOOST_REQUIRE(plane.cursor() == 1);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
