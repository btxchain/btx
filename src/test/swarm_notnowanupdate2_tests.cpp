// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnowanupdate2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnowanupdate2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoWanUpdate2 NotedNote()
{
    modelnet::SwarmNotNoWanUpdate2 note;
    note.island_id = "island-1";
    note.want_exchange = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_island_id_is_island)
{
    modelnet::SwarmNotNoWanUpdate2 note = NotedNote();
    note.island_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotNoWanUpdate2Result result = modelnet::SwarmNoteNotNoWanUpdate2(note, err);
    BOOST_CHECK(!result.exchanged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ISLAND");
    BOOST_CHECK_EQUAL(err, "ISLAND");
}

BOOST_AUTO_TEST_CASE(want_exchange_is_held)
{
    modelnet::SwarmNotNoWanUpdate2 note = NotedNote();
    note.want_exchange = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoWanUpdate2Result result = modelnet::SwarmNoteNotNoWanUpdate2(note, err);
    BOOST_CHECK(!result.exchanged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoWanUpdate2 note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoWanUpdate2Result result = modelnet::SwarmNoteNotNoWanUpdate2(note, err);
    BOOST_CHECK(!result.exchanged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
