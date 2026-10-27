// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_bodygate/swarm_bodygate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>

BOOST_FIXTURE_TEST_SUITE(swarm_bodygate_piece_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(short_non_last_piece_stores_nothing)
{
    modelnet::SwarmBodyGate gate;
    BOOST_CHECK(!gate.AddPiece(0, gate.piece_bytes() - 1, false));
    BOOST_CHECK_EQUAL(gate.code(), "SHORT");
    BOOST_CHECK(!gate.has_piece(0));
    BOOST_CHECK_EQUAL(gate.piece_count(), int64_t{0});
    BOOST_CHECK_EQUAL(gate.stored_bytes(), int64_t{0});
    BOOST_CHECK(!gate.joined());
    BOOST_CHECK_EQUAL(gate.bytes(), int64_t{0});
    BOOST_CHECK_EQUAL(gate.bytes_moved(), int64_t{0});

    BOOST_CHECK(!gate.AddPiece(1, int64_t{1}, false));
    BOOST_CHECK_EQUAL(gate.code(), "SHORT");
    BOOST_CHECK(!gate.has_piece(1));

    BOOST_CHECK(!gate.AddPiece(2, gate.piece_bytes() + 1, false));
    BOOST_CHECK_EQUAL(gate.code(), "SHORT");
    BOOST_CHECK(!gate.has_piece(2));
    BOOST_CHECK_EQUAL(gate.piece_count(), int64_t{0});
}

BOOST_AUTO_TEST_CASE(four_mib_piece_is_stored)
{
    modelnet::SwarmBodyGate gate;
    BOOST_REQUIRE_EQUAL(gate.piece_bytes(), int64_t{4194304});
    BOOST_REQUIRE(gate.AddPiece(0, gate.piece_bytes(), false));
    BOOST_REQUIRE_EQUAL(gate.code(), "OK");
    BOOST_REQUIRE(gate.has_piece(0));
    BOOST_REQUIRE_EQUAL(gate.piece_size(0), int64_t{4194304});
    BOOST_REQUIRE(!gate.piece_last(0));
    BOOST_REQUIRE_EQUAL(gate.piece_count(), int64_t{1});
    BOOST_REQUIRE_EQUAL(gate.stored_bytes(), int64_t{4194304});
    BOOST_REQUIRE(!gate.joined());
    BOOST_REQUIRE_EQUAL(gate.bytes(), int64_t{0});
    BOOST_REQUIRE_EQUAL(gate.bytes_moved(), int64_t{0});

    BOOST_REQUIRE(gate.AddPiece(1, gate.piece_bytes(), true));
    BOOST_REQUIRE(gate.piece_last(1));
    BOOST_REQUIRE_EQUAL(gate.piece_size(1), gate.piece_bytes());
    BOOST_REQUIRE_EQUAL(gate.bytes_moved(), int64_t{0});
}

BOOST_AUTO_TEST_CASE(body_past_32mib_is_not_stored)
{
    modelnet::SwarmBodyGate gate;
    BOOST_REQUIRE_EQUAL(gate.body_cap(), int64_t{33554432});
    for (int64_t index = 0; index < 8; ++index) {
        BOOST_REQUIRE(gate.AddPiece(index, gate.piece_bytes(), false));
    }
    BOOST_REQUIRE_EQUAL(gate.piece_count(), int64_t{8});
    BOOST_REQUIRE_EQUAL(gate.stored_bytes(), gate.body_cap());
    BOOST_REQUIRE_EQUAL(gate.bytes_moved(), int64_t{0});

    BOOST_CHECK(!gate.AddPiece(8, gate.piece_bytes(), false));
    BOOST_CHECK_EQUAL(gate.code(), "BODY");
    BOOST_CHECK(!gate.has_piece(8));
    BOOST_CHECK_EQUAL(gate.piece_count(), int64_t{8});
    BOOST_CHECK_EQUAL(gate.stored_bytes(), gate.body_cap());
    BOOST_CHECK_EQUAL(gate.bytes_moved(), int64_t{0});

    BOOST_CHECK(!gate.AddPiece(8, int64_t{1}, true));
    BOOST_CHECK_EQUAL(gate.code(), "BODY");
    BOOST_CHECK(!gate.has_piece(8));
    BOOST_CHECK_EQUAL(gate.stored_bytes(), int64_t{33554432});

    BOOST_CHECK(!gate.AddPiece(0, gate.piece_bytes(), false));
    BOOST_CHECK_EQUAL(gate.code(), "REPLAY");
    BOOST_REQUIRE_EQUAL(gate.piece_count(), int64_t{8});
    BOOST_REQUIRE_EQUAL(gate.piece_size(0), gate.piece_bytes());
    BOOST_REQUIRE_EQUAL(gate.stored_bytes(), gate.body_cap());
}

BOOST_AUTO_TEST_CASE(negative_index_is_index_and_stores_nothing)
{
    modelnet::SwarmBodyGate gate;
    BOOST_CHECK(!gate.AddPiece(-1, gate.piece_bytes(), true));
    BOOST_CHECK_EQUAL(gate.code(), "INDEX");
    BOOST_CHECK(!gate.has_piece(-1));
    BOOST_CHECK_EQUAL(gate.piece_count(), int64_t{0});
    BOOST_CHECK_EQUAL(gate.bytes_moved(), int64_t{0});

    BOOST_CHECK(!gate.AddPiece(-1, int64_t{0}, false));
    BOOST_CHECK_EQUAL(gate.code(), "INDEX");
    BOOST_CHECK_EQUAL(gate.piece_count(), int64_t{0});
}

BOOST_AUTO_TEST_CASE(size_below_one_is_short)
{
    modelnet::SwarmBodyGate gate;
    BOOST_CHECK(!gate.AddPiece(0, int64_t{0}, true));
    BOOST_CHECK_EQUAL(gate.code(), "SHORT");
    BOOST_CHECK(!gate.has_piece(0));

    BOOST_CHECK(!gate.AddPiece(0, int64_t{-5}, true));
    BOOST_CHECK_EQUAL(gate.code(), "SHORT");
    BOOST_CHECK_EQUAL(gate.piece_count(), int64_t{0});
    BOOST_CHECK_EQUAL(gate.stored_bytes(), int64_t{0});
}

BOOST_AUTO_TEST_CASE(last_piece_above_piece_size_is_short)
{
    modelnet::SwarmBodyGate gate;
    BOOST_CHECK(!gate.AddPiece(0, gate.piece_bytes() + 1, true));
    BOOST_CHECK_EQUAL(gate.code(), "SHORT");
    BOOST_CHECK(!gate.has_piece(0));
    BOOST_CHECK_EQUAL(gate.stored_bytes(), int64_t{0});
    BOOST_CHECK_EQUAL(gate.bytes_moved(), int64_t{0});
}

BOOST_AUTO_TEST_CASE(duplicate_index_is_replay_and_keeps_first_size)
{
    modelnet::SwarmBodyGate gate;
    BOOST_REQUIRE(gate.AddPiece(3, int64_t{100}, true));
    BOOST_REQUIRE_EQUAL(gate.piece_size(3), int64_t{100});
    BOOST_REQUIRE(gate.piece_last(3));

    BOOST_CHECK(!gate.AddPiece(3, gate.piece_bytes(), false));
    BOOST_CHECK_EQUAL(gate.code(), "REPLAY");
    BOOST_REQUIRE_EQUAL(gate.piece_size(3), int64_t{100});
    BOOST_REQUIRE(gate.piece_last(3));
    BOOST_REQUIRE_EQUAL(gate.piece_count(), int64_t{1});
    BOOST_REQUIRE_EQUAL(gate.stored_bytes(), int64_t{100});
    BOOST_REQUIRE_EQUAL(gate.bytes_moved(), int64_t{0});
}

BOOST_AUTO_TEST_CASE(short_duplicate_is_short_and_keeps_first_size)
{
    modelnet::SwarmBodyGate gate;
    BOOST_REQUIRE(gate.AddPiece(0, gate.piece_bytes(), false));
    BOOST_CHECK(!gate.AddPiece(0, int64_t{10}, false));
    BOOST_CHECK_EQUAL(gate.code(), "SHORT");
    BOOST_REQUIRE_EQUAL(gate.piece_size(0), gate.piece_bytes());
    BOOST_REQUIRE(!gate.piece_last(0));
    BOOST_REQUIRE_EQUAL(gate.piece_count(), int64_t{1});
}

BOOST_AUTO_TEST_SUITE_END()
