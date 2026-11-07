// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoisland.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoisland_tests, BasicTestingSetup)

static modelnet::SwarmNotNoIsland NotedNote()
{
    modelnet::SwarmNotNoIsland note;
    note.island_id = "island-1";
    note.stale = false;
    note.want_average = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_island_id_is_island)
{
    modelnet::SwarmNotNoIsland note = NotedNote();
    note.island_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotNoIslandResult result = modelnet::SwarmNoteNotNoIsland(note, err);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ISLAND");
    BOOST_CHECK_EQUAL(err, "ISLAND");
}

BOOST_AUTO_TEST_CASE(stale_island_is_stale)
{
    modelnet::SwarmNotNoIsland note = NotedNote();
    note.stale = true;
    note.want_average = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoIslandResult result = modelnet::SwarmNoteNotNoIsland(note, err);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "STALE");
    BOOST_CHECK_EQUAL(err, "STALE");
}

BOOST_AUTO_TEST_CASE(want_average_while_fresh_is_held)
{
    modelnet::SwarmNotNoIsland note = NotedNote();
    note.stale = false;
    note.want_average = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoIslandResult result = modelnet::SwarmNoteNotNoIsland(note, err);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(fresh_plain_note_is_noted)
{
    modelnet::SwarmNotNoIsland note = NotedNote();
    note.stale = false;
    note.want_average = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoIslandResult result = modelnet::SwarmNoteNotNoIsland(note, err);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
