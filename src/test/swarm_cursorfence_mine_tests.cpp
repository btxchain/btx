// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cursorfence/swarm_cursorfence.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_cursorfence_mine_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(mine_before_any_advance_is_held_and_blocks_stay_zero)
{
    modelnet::SwarmCursorFence plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.cursor() == 0);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);

    BOOST_REQUIRE(!plane.Mine(err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.cursor() == 0);
    BOOST_REQUIRE(!plane.committed(0));
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Mine(err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.blocks() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_CASE(mine_after_advance_and_conflict_stays_held)
{
    modelnet::SwarmCursorFence plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Advance(1, err));
    BOOST_REQUIRE(plane.Commit(1, "hash-a", err));
    BOOST_REQUIRE(!plane.Commit(1, "hash-b", err));
    BOOST_REQUIRE_EQUAL(err, "CONFLICT");
    BOOST_REQUIRE_EQUAL(plane.hash_at(1), "hash-a");

    err = "prior";
    BOOST_REQUIRE(!plane.Mine(err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.cursor() == 1);
    BOOST_REQUIRE_EQUAL(plane.hash_at(1), "hash-a");
    BOOST_REQUIRE(plane.committed(1));
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);

    BOOST_REQUIRE(plane.Advance(2, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.cursor() == 2);

    err = "prior";
    BOOST_REQUIRE(!plane.Mine(err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.cursor() == 2);
    BOOST_REQUIRE_EQUAL(plane.hash_at(1), "hash-a");
    BOOST_REQUIRE(!plane.committed(2));
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);

    BOOST_REQUIRE(!plane.Advance(2, err));
    BOOST_REQUIRE_EQUAL(err, "STALE");
    BOOST_REQUIRE(!plane.Advance(4, err));
    BOOST_REQUIRE_EQUAL(err, "GAP");
    BOOST_REQUIRE(!plane.Mine(err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.cursor() == 2);
    BOOST_REQUIRE(plane.blocks() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
