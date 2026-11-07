// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notdiloco.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notdiloco_tests, BasicTestingSetup)

static modelnet::SwarmNotDiloco NotedNote()
{
    modelnet::SwarmNotDiloco note;
    note.island_id = "island-1";
    note.want_average = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_island_id_is_island)
{
    modelnet::SwarmNotDiloco note = NotedNote();
    note.island_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotDilocoResult result = modelnet::SwarmNoteNotDiloco(note, err);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ISLAND");
    BOOST_CHECK_EQUAL(err, "ISLAND");
}

BOOST_AUTO_TEST_CASE(want_average_is_not_averaged)
{
    modelnet::SwarmNotDiloco note = NotedNote();
    note.want_average = true;
    std::string err = "prior";
    const modelnet::SwarmNotDilocoResult result = modelnet::SwarmNoteNotDiloco(note, err);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_AVERAGED");
    BOOST_CHECK_EQUAL(err, "NOT_AVERAGED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotDiloco note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotDilocoResult result = modelnet::SwarmNoteNotDiloco(note, err);
    BOOST_CHECK(!result.averaged);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
