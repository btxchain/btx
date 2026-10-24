// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnospawn.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnospawn_tests, BasicTestingSetup)

static modelnet::SwarmNotNoSpawn NotedNote()
{
    modelnet::SwarmNotNoSpawn note;
    note.node_id = "node-a";
    note.want_exec = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmNotNoSpawn note = NotedNote();
    note.node_id.clear();
    note.want_exec = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSpawnResult result = modelnet::SwarmNoteNotNoSpawn(note, err);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK(!result.external);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_exec_is_not_launched)
{
    modelnet::SwarmNotNoSpawn note = NotedNote();
    note.want_exec = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSpawnResult result = modelnet::SwarmNoteNotNoSpawn(note, err);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK(!result.external);
    BOOST_CHECK_EQUAL(result.code, "NOT_LAUNCHED");
    BOOST_CHECK_EQUAL(err, "NOT_LAUNCHED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoSpawn note = NotedNote();
    note.want_exec = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSpawnResult result = modelnet::SwarmNoteNotNoSpawn(note, err);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK(!result.external);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
