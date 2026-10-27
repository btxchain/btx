// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnostale2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnostale2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoStale2 NotedNote()
{
    modelnet::SwarmNotNoStale2 note;
    note.island_id = "island-1";
    note.stale = false;
    note.want_admit = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_island_id_is_island)
{
    modelnet::SwarmNotNoStale2 note = NotedNote();
    note.island_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotNoStale2Result result = modelnet::SwarmNoteNotNoStale2(note, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ISLAND");
    BOOST_CHECK_EQUAL(err, "ISLAND");
}

BOOST_AUTO_TEST_CASE(stale_island_is_not_admitted)
{
    modelnet::SwarmNotNoStale2 note = NotedNote();
    note.stale = true;
    note.want_admit = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoStale2Result result = modelnet::SwarmNoteNotNoStale2(note, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_ADMITTED");
    BOOST_CHECK_EQUAL(err, "NOT_ADMITTED");
}

BOOST_AUTO_TEST_CASE(want_admit_while_fresh_is_held)
{
    modelnet::SwarmNotNoStale2 note = NotedNote();
    note.stale = false;
    note.want_admit = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoStale2Result result = modelnet::SwarmNoteNotNoStale2(note, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(fresh_plain_note_is_noted)
{
    modelnet::SwarmNotNoStale2 note = NotedNote();
    note.stale = false;
    note.want_admit = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoStale2Result result = modelnet::SwarmNoteNotNoStale2(note, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
