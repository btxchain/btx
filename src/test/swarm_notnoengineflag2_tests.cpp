// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoengineflag2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoengineflag2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_transfer_id_is_transfer)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEngineFlag2 note;
    note.engine_flag = false;
    note.want_move = true;
    const modelnet::SwarmNotNoEngineFlag2Result result = modelnet::SwarmNoteNotNoEngineFlag2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "TRANSFER");
    BOOST_CHECK_EQUAL(err, "TRANSFER");
}

BOOST_AUTO_TEST_CASE(engine_flag_is_not_transfer)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEngineFlag2 note;
    note.transfer_id = "transfer-1";
    note.engine_flag = true;
    note.want_move = false;
    const modelnet::SwarmNotNoEngineFlag2Result result = modelnet::SwarmNoteNotNoEngineFlag2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_TRANSFER");
    BOOST_CHECK_EQUAL(err, "NOT_TRANSFER");
}

BOOST_AUTO_TEST_CASE(want_move_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEngineFlag2 note;
    note.transfer_id = "transfer-1";
    note.engine_flag = false;
    note.want_move = true;
    const modelnet::SwarmNotNoEngineFlag2Result result = modelnet::SwarmNoteNotNoEngineFlag2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEngineFlag2 note;
    note.transfer_id = "transfer-1";
    note.engine_flag = false;
    note.want_move = false;
    const modelnet::SwarmNotNoEngineFlag2Result result = modelnet::SwarmNoteNotNoEngineFlag2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
