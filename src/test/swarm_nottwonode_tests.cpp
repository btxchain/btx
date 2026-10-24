// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nottwonode.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_nottwonode_tests, BasicTestingSetup)

static modelnet::SwarmNotTwoNode NotedNote()
{
    modelnet::SwarmNotTwoNode note;
    note.node_id = "node-1";
    note.want_pair = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmNotTwoNode note = NotedNote();
    note.node_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotTwoNodeResult result = modelnet::SwarmNoteNotTwoNode(note, err);
    BOOST_CHECK(!result.paired);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_pair_is_out_of_scope)
{
    modelnet::SwarmNotTwoNode note = NotedNote();
    note.want_pair = true;
    std::string err = "prior";
    const modelnet::SwarmNotTwoNodeResult result = modelnet::SwarmNoteNotTwoNode(note, err);
    BOOST_CHECK(!result.paired);
    BOOST_CHECK_EQUAL(result.code, "OUT_OF_SCOPE");
    BOOST_CHECK_EQUAL(err, "OUT_OF_SCOPE");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotTwoNode note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotTwoNodeResult result = modelnet::SwarmNoteNotTwoNode(note, err);
    BOOST_CHECK(!result.paired);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
