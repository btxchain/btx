// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnokvmove2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnokvmove2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoKvMove2 NotedNote()
{
    modelnet::SwarmNotNoKvMove2 note;
    note.transfer_id = "transfer-1";
    note.want_move = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_transfer_id_is_transfer)
{
    modelnet::SwarmNotNoKvMove2 note = NotedNote();
    note.transfer_id.clear();
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoKvMove2Result result = modelnet::SwarmNoteNotNoKvMove2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "TRANSFER");
    BOOST_CHECK_EQUAL(err, "TRANSFER");
}

BOOST_AUTO_TEST_CASE(want_move_is_held)
{
    modelnet::SwarmNotNoKvMove2 note = NotedNote();
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoKvMove2Result result = modelnet::SwarmNoteNotNoKvMove2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoKvMove2 note = NotedNote();
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoKvMove2Result result = modelnet::SwarmNoteNotNoKvMove2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
