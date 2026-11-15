// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_piecejoin.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_piecejoin_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(two_full_pieces_and_short_last_join_in_order)
{
    modelnet::SwarmPieceJoin pieces;
    const std::string first(32, 'A');
    const std::string second(32, 'B');
    const std::string last = "tail";
    std::string err = "prior";
    std::string out = "stale";

    BOOST_REQUIRE(pieces.Add(2, last, err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(pieces.Add(0, first, err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(pieces.Add(1, second, err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(!pieces.Add(0, std::string(32, 'C'), err));
    BOOST_CHECK_EQUAL(err, "REPLAY");

    out = "stale";
    BOOST_REQUIRE(pieces.Join(out, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(out, first + second + last);
}

BOOST_AUTO_TEST_CASE(gap_refuses_and_leaves_pieces)
{
    modelnet::SwarmPieceJoin pieces;
    const std::string first(32, 'A');
    const std::string middle(32, 'B');
    const std::string last = "end";
    std::string err = "prior";
    std::string out = "stale";

    BOOST_REQUIRE(pieces.Add(0, first, err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(pieces.Add(2, last, err));
    BOOST_CHECK(err.empty());

    out = "stale";
    err = "prior";
    BOOST_CHECK(!pieces.Join(out, err));
    BOOST_CHECK_EQUAL(err, "GAP");
    BOOST_CHECK(out.empty());

    BOOST_REQUIRE(pieces.Add(1, middle, err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(pieces.Join(out, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(out, first + middle + last);
}

BOOST_AUTO_TEST_CASE(short_first_piece_refuses)
{
    modelnet::SwarmPieceJoin pieces;
    const std::string first = "tiny";
    const std::string last(32, 'Z');
    std::string err = "prior";
    std::string out = "stale";

    BOOST_REQUIRE(pieces.Add(0, first, err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(pieces.Add(1, last, err));
    BOOST_CHECK(err.empty());

    out = "stale";
    err = "prior";
    BOOST_CHECK(!pieces.Join(out, err));
    BOOST_CHECK_EQUAL(err, "SHORT");
    BOOST_CHECK(out.empty());
}

BOOST_AUTO_TEST_SUITE_END()
