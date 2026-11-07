// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomoon2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnomoon2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_adapter_id_is_adapter)
{
    std::string err = "prior";
    modelnet::SwarmNotNoMoon2 note;
    note.present = false;
    note.want_move = true;
    const modelnet::SwarmNotNoMoon2Result result = modelnet::SwarmNoteNotNoMoon2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ADAPTER");
    BOOST_CHECK_EQUAL(err, "ADAPTER");
}

BOOST_AUTO_TEST_CASE(missing_adapter_is_engine_absent)
{
    std::string err = "prior";
    modelnet::SwarmNotNoMoon2 note;
    note.adapter_id = "adapter-1";
    note.present = false;
    note.want_move = false;
    const modelnet::SwarmNotNoMoon2Result result = modelnet::SwarmNoteNotNoMoon2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(want_move_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoMoon2 note;
    note.adapter_id = "adapter-1";
    note.present = true;
    note.want_move = true;
    const modelnet::SwarmNotNoMoon2Result result = modelnet::SwarmNoteNotNoMoon2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoMoon2 note;
    note.adapter_id = "adapter-1";
    note.present = true;
    note.want_move = false;
    const modelnet::SwarmNotNoMoon2Result result = modelnet::SwarmNoteNotNoMoon2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
