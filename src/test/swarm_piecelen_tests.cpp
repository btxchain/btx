// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_piecelen.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_piecelen_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(accept_piece_length)
{
    modelnet::SwarmPieceLen len;
    std::string err;

    BOOST_CHECK(!len.Accept(0, false, err));
    BOOST_CHECK_EQUAL(err, "SHORT");
    BOOST_CHECK(!len.bytes_moved());
    BOOST_CHECK_EQUAL(len.piece_bytes(), 4194304);

    BOOST_CHECK(!len.Accept(4194303, false, err));
    BOOST_CHECK_EQUAL(err, "SHORT");
    BOOST_CHECK(!len.bytes_moved());
    BOOST_CHECK_EQUAL(len.piece_bytes(), 4194304);

    BOOST_CHECK(!len.Accept(4194305, false, err));
    BOOST_CHECK_EQUAL(err, "SHORT");
    BOOST_CHECK(!len.bytes_moved());
    BOOST_CHECK_EQUAL(len.piece_bytes(), 4194304);

    err = "stale";
    BOOST_REQUIRE(len.Accept(4194304, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!len.bytes_moved());
    BOOST_CHECK_EQUAL(len.piece_bytes(), 4194304);

    err = "stale";
    BOOST_REQUIRE(len.Accept(4194304, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!len.bytes_moved());
    BOOST_CHECK_EQUAL(len.piece_bytes(), 4194304);

    err = "stale";
    BOOST_REQUIRE(len.Accept(1, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!len.bytes_moved());
    BOOST_CHECK_EQUAL(len.piece_bytes(), 4194304);

    BOOST_CHECK(!len.Accept(4194305, true, err));
    BOOST_CHECK_EQUAL(err, "SHORT");
    BOOST_CHECK(!len.bytes_moved());
    BOOST_CHECK_EQUAL(len.piece_bytes(), 4194304);
}

BOOST_AUTO_TEST_SUITE_END()
