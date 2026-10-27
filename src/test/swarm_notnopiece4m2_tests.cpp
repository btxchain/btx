// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopiece4m2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnopiece4m2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_piece_id)
{
    modelnet::SwarmNotNoPiece4m2 note;
    std::string err = "stale";
    const modelnet::SwarmNotNoPiece4m2Result result = modelnet::SwarmNoteNotNoPiece4m2(note, err);
    BOOST_CHECK_EQUAL(result.code, "PIECE");
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK(!result.resized);
    BOOST_CHECK_EQUAL(result.bytes, 4194304);
}

BOOST_AUTO_TEST_CASE(want_resize_true)
{
    modelnet::SwarmNotNoPiece4m2 note;
    note.piece_id = "piece-1";
    note.want_resize = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoPiece4m2Result result = modelnet::SwarmNoteNotNoPiece4m2(note, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!result.resized);
    BOOST_CHECK_EQUAL(result.bytes, 4194304);
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    modelnet::SwarmNotNoPiece4m2 note;
    note.piece_id = "piece-1";
    note.want_resize = false;
    std::string err = "stale";
    const modelnet::SwarmNotNoPiece4m2Result result = modelnet::SwarmNoteNotNoPiece4m2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.resized);
    BOOST_CHECK_EQUAL(result.bytes, 4194304);
}

BOOST_AUTO_TEST_SUITE_END()
