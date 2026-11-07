// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notsurvivor.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notsurvivor_tests, BasicTestingSetup)

static modelnet::SwarmNotSurvivor NotedNote()
{
    modelnet::SwarmNotSurvivor note;
    note.node_id = "node-1";
    note.want_continue = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmNotSurvivor note = NotedNote();
    note.node_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotSurvivorResult result = modelnet::SwarmNoteNotSurvivor(note, err);
    BOOST_CHECK(!result.continued);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_continue_is_not_shown)
{
    modelnet::SwarmNotSurvivor note = NotedNote();
    note.want_continue = true;
    std::string err = "prior";
    const modelnet::SwarmNotSurvivorResult result = modelnet::SwarmNoteNotSurvivor(note, err);
    BOOST_CHECK(!result.continued);
    BOOST_CHECK_EQUAL(result.code, "NOT_SHOWN");
    BOOST_CHECK_EQUAL(err, "NOT_SHOWN");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotSurvivor note = NotedNote();
    note.want_continue = false;
    std::string err = "prior";
    const modelnet::SwarmNotSurvivorResult result = modelnet::SwarmNoteNotSurvivor(note, err);
    BOOST_CHECK(!result.continued);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
