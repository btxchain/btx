// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_piecekeep.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_piecekeep_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_piece_id_yields_piece)
{
    modelnet::SwarmPieceKeep piece;
    piece.piece_id.clear();
    piece.want_resize = false;
    std::string err = "stale";
    const modelnet::SwarmPieceKeepResult result = modelnet::SwarmKeepPieceSplit(piece, err);
    BOOST_CHECK(!result.resized);
    BOOST_CHECK_EQUAL(result.bytes, static_cast<int64_t>(4194304));
    BOOST_CHECK_EQUAL(result.code, "PIECE");
    BOOST_CHECK_EQUAL(err, "PIECE");
}

BOOST_AUTO_TEST_CASE(want_resize_yields_held)
{
    modelnet::SwarmPieceKeep piece;
    piece.piece_id = "piece-a";
    piece.want_resize = true;
    std::string err;
    const modelnet::SwarmPieceKeepResult result = modelnet::SwarmKeepPieceSplit(piece, err);
    BOOST_CHECK(!result.resized);
    BOOST_CHECK_EQUAL(result.bytes, static_cast<int64_t>(4194304));
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(keep_split_yields_noted)
{
    modelnet::SwarmPieceKeep piece;
    piece.piece_id = "piece-b";
    piece.want_resize = false;
    std::string err = "stale";
    const modelnet::SwarmPieceKeepResult result = modelnet::SwarmKeepPieceSplit(piece, err);
    BOOST_CHECK(!result.resized);
    BOOST_CHECK_EQUAL(result.bytes, static_cast<int64_t>(4194304));
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
