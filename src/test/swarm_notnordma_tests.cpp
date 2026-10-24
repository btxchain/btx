// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnordma.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnordma_tests, BasicTestingSetup)

static modelnet::SwarmNotNoRdma NotedNote()
{
    modelnet::SwarmNotNoRdma note;
    note.link_id = "link-1";
    note.want_move = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_link_id_is_link)
{
    modelnet::SwarmNotNoRdma note = NotedNote();
    note.link_id.clear();
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoRdmaResult result = modelnet::SwarmNoteNotNoRdma(note, err);
    BOOST_CHECK_EQUAL(result.code, "LINK");
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(err, "LINK");
}

BOOST_AUTO_TEST_CASE(want_move_is_engine_absent)
{
    modelnet::SwarmNotNoRdma note = NotedNote();
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoRdmaResult result = modelnet::SwarmNoteNotNoRdma(note, err);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoRdma note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoRdmaResult result = modelnet::SwarmNoteNotNoRdma(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
