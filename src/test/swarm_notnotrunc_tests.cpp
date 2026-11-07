// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotrunc.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnotrunc_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_piece_id_is_piece)
{
    modelnet::SwarmNotNoTrunc note;
    note.truncated = true;
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoTruncResult result = modelnet::SwarmNoteNotNoTrunc(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "PIECE");
    BOOST_CHECK_EQUAL(err, "PIECE");
}

BOOST_AUTO_TEST_CASE(truncated_is_not_moved_when_want_move_is_false)
{
    modelnet::SwarmNotNoTrunc note;
    note.piece_id = "piece-1";
    note.truncated = true;
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoTruncResult result = modelnet::SwarmNoteNotNoTrunc(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_MOVED");
    BOOST_CHECK_EQUAL(err, "NOT_MOVED");
}

BOOST_AUTO_TEST_CASE(want_move_is_held)
{
    modelnet::SwarmNotNoTrunc note;
    note.piece_id = "piece-1";
    note.truncated = false;
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoTruncResult result = modelnet::SwarmNoteNotNoTrunc(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoTrunc note;
    note.piece_id = "piece-1";
    note.truncated = false;
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoTruncResult result = modelnet::SwarmNoteNotNoTrunc(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
