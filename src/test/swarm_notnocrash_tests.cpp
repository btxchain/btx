// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocrash.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocrash_tests, BasicTestingSetup)

static modelnet::SwarmNotNoCrash NotedNote()
{
    modelnet::SwarmNotNoCrash note;
    note.node_id = "node-1";
    note.crashed = false;
    note.want_spend = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmNotNoCrash note = NotedNote();
    note.node_id.clear();
    note.crashed = true;
    note.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCrashResult result = modelnet::SwarmNoteNotNoCrash(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(crashed_is_held)
{
    modelnet::SwarmNotNoCrash note = NotedNote();
    note.crashed = true;
    note.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCrashResult result = modelnet::SwarmNoteNotNoCrash(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_spend_while_not_crashed_is_held)
{
    modelnet::SwarmNotNoCrash note = NotedNote();
    note.crashed = false;
    note.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCrashResult result = modelnet::SwarmNoteNotNoCrash(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_is_noted)
{
    modelnet::SwarmNotNoCrash note = NotedNote();
    note.crashed = false;
    note.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCrashResult result = modelnet::SwarmNoteNotNoCrash(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
