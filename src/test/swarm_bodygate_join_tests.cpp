// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_bodygate/swarm_bodygate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>

BOOST_FIXTURE_TEST_SUITE(swarm_bodygate_join_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(contiguous_join_sums_sizes_and_moves_no_bytes)
{
    modelnet::SwarmBodyGate gate;
    BOOST_REQUIRE(gate.AddPiece(1, int64_t{2048}, true));
    BOOST_REQUIRE(gate.AddPiece(0, gate.piece_bytes(), false));
    BOOST_REQUIRE(gate.Join());
    BOOST_REQUIRE(gate.joined());
    BOOST_REQUIRE_EQUAL(gate.code(), "OK");
    BOOST_REQUIRE_EQUAL(gate.bytes(), gate.piece_bytes() + int64_t{2048});
    BOOST_REQUIRE_EQUAL(gate.stored_bytes(), gate.bytes());
    BOOST_REQUIRE_EQUAL(gate.bytes_moved(), int64_t{0});

    BOOST_CHECK(!gate.AddPiece(0, gate.piece_bytes(), false));
    BOOST_CHECK_EQUAL(gate.code(), "REPLAY");
    BOOST_REQUIRE(gate.joined());
    BOOST_REQUIRE_EQUAL(gate.bytes(), gate.piece_bytes() + int64_t{2048});
    BOOST_REQUIRE_EQUAL(gate.bytes_moved(), int64_t{0});
}

BOOST_AUTO_TEST_CASE(exact_body_cap_joins_and_moves_no_bytes)
{
    modelnet::SwarmBodyGate gate;
    for (int64_t index = 0; index < 7; ++index) {
        BOOST_REQUIRE(gate.AddPiece(index, gate.piece_bytes(), false));
    }
    BOOST_REQUIRE(gate.AddPiece(7, gate.piece_bytes(), true));
    BOOST_REQUIRE_EQUAL(gate.stored_bytes(), gate.body_cap());
    BOOST_REQUIRE(gate.Join());
    BOOST_REQUIRE(gate.joined());
    BOOST_REQUIRE_EQUAL(gate.bytes(), int64_t{33554432});
    BOOST_REQUIRE_EQUAL(gate.bytes_moved(), int64_t{0});
}

BOOST_AUTO_TEST_CASE(single_last_piece_joins)
{
    modelnet::SwarmBodyGate gate;
    BOOST_REQUIRE(gate.AddPiece(0, int64_t{1}, true));
    BOOST_REQUIRE(gate.Join());
    BOOST_REQUIRE(gate.joined());
    BOOST_REQUIRE_EQUAL(gate.bytes(), int64_t{1});
    BOOST_REQUIRE_EQUAL(gate.bytes_moved(), int64_t{0});
}

BOOST_AUTO_TEST_CASE(gap_is_not_joined)
{
    modelnet::SwarmBodyGate gate;
    BOOST_REQUIRE(gate.AddPiece(0, gate.piece_bytes(), false));
    BOOST_REQUIRE(gate.AddPiece(2, int64_t{64}, true));
    BOOST_CHECK(!gate.Join());
    BOOST_CHECK(!gate.joined());
    BOOST_CHECK_EQUAL(gate.code(), "GAP");
    BOOST_CHECK_EQUAL(gate.bytes(), int64_t{0});
    BOOST_CHECK_EQUAL(gate.bytes_moved(), int64_t{0});
    BOOST_REQUIRE_EQUAL(gate.piece_count(), int64_t{2});
    BOOST_REQUIRE_EQUAL(gate.stored_bytes(), gate.piece_bytes() + int64_t{64});
}

BOOST_AUTO_TEST_CASE(missing_last_piece_is_last)
{
    modelnet::SwarmBodyGate gate;
    BOOST_CHECK(!gate.Join());
    BOOST_CHECK_EQUAL(gate.code(), "LAST");
    BOOST_CHECK(!gate.joined());
    BOOST_CHECK_EQUAL(gate.bytes(), int64_t{0});
    BOOST_CHECK_EQUAL(gate.bytes_moved(), int64_t{0});

    BOOST_REQUIRE(gate.AddPiece(0, gate.piece_bytes(), false));
    BOOST_REQUIRE(gate.AddPiece(1, gate.piece_bytes(), false));
    BOOST_CHECK(!gate.Join());
    BOOST_CHECK_EQUAL(gate.code(), "LAST");
    BOOST_CHECK(!gate.joined());
    BOOST_CHECK_EQUAL(gate.bytes(), int64_t{0});
    BOOST_REQUIRE_EQUAL(gate.piece_count(), int64_t{2});
}

BOOST_AUTO_TEST_CASE(last_piece_must_be_the_highest_index)
{
    modelnet::SwarmBodyGate gate;
    BOOST_REQUIRE(gate.AddPiece(0, int64_t{32}, true));
    BOOST_REQUIRE(gate.AddPiece(1, gate.piece_bytes(), false));
    BOOST_CHECK(!gate.Join());
    BOOST_CHECK(!gate.joined());
    BOOST_CHECK_EQUAL(gate.code(), "LAST");
    BOOST_CHECK_EQUAL(gate.bytes(), int64_t{0});
    BOOST_CHECK_EQUAL(gate.bytes_moved(), int64_t{0});
}

BOOST_AUTO_TEST_CASE(two_last_pieces_are_last)
{
    modelnet::SwarmBodyGate gate;
    BOOST_REQUIRE(gate.AddPiece(0, int64_t{32}, true));
    BOOST_REQUIRE(gate.AddPiece(1, int64_t{32}, true));
    BOOST_CHECK(!gate.Join());
    BOOST_CHECK_EQUAL(gate.code(), "LAST");
    BOOST_CHECK(!gate.joined());
    BOOST_CHECK_EQUAL(gate.bytes_moved(), int64_t{0});
}

BOOST_AUTO_TEST_CASE(a_new_piece_clears_joined)
{
    modelnet::SwarmBodyGate gate;
    BOOST_REQUIRE(gate.AddPiece(0, int64_t{8}, true));
    BOOST_REQUIRE(gate.Join());
    BOOST_REQUIRE(gate.joined());
    BOOST_REQUIRE_EQUAL(gate.bytes_moved(), int64_t{0});

    BOOST_REQUIRE(gate.AddPiece(1, int64_t{8}, true));
    BOOST_REQUIRE(!gate.joined());
    BOOST_REQUIRE_EQUAL(gate.bytes(), int64_t{0});
    BOOST_REQUIRE_EQUAL(gate.bytes_moved(), int64_t{0});
    BOOST_CHECK(!gate.Join());
    BOOST_CHECK_EQUAL(gate.code(), "LAST");
}

BOOST_AUTO_TEST_SUITE_END()
