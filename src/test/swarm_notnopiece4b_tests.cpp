// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopiece4b.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnopiece4b_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_piece_id)
{
    modelnet::SwarmNotNoPiece4b note;
    std::string err = "stale";
    const modelnet::SwarmNotNoPiece4bResult result = modelnet::SwarmNoteNotNoPiece4b(note, err);
    BOOST_CHECK_EQUAL(result.code, "PIECE");
    BOOST_CHECK(!result.split);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(err, "PIECE");
}

BOOST_AUTO_TEST_CASE(bytes_1)
{
    modelnet::SwarmNotNoPiece4b note;
    note.piece_id = "piece-1";
    note.bytes = 1;
    note.want_split = false;
    std::string err = "stale";
    const modelnet::SwarmNotNoPiece4bResult result = modelnet::SwarmNoteNotNoPiece4b(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_SPLIT");
    BOOST_CHECK(!result.split);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(err, "NOT_SPLIT");
}

BOOST_AUTO_TEST_CASE(want_split_bytes_4194304)
{
    modelnet::SwarmNotNoPiece4b note;
    note.piece_id = "piece-1";
    note.bytes = 4194304;
    note.want_split = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoPiece4bResult result = modelnet::SwarmNoteNotNoPiece4b(note, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.split);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(quiet_note_bytes_4194304)
{
    modelnet::SwarmNotNoPiece4b note;
    note.piece_id = "piece-1";
    note.bytes = 4194304;
    note.want_split = false;
    std::string err = "stale";
    const modelnet::SwarmNotNoPiece4bResult result = modelnet::SwarmNoteNotNoPiece4b(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.split);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
