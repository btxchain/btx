// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notraft.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notraft_tests, BasicTestingSetup)

static modelnet::SwarmNotRaft NotedNote()
{
    modelnet::SwarmNotRaft note;
    note.node_id = "node-1";
    note.want_cluster = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmNotRaft note = NotedNote();
    note.node_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotRaftResult result = modelnet::SwarmNoteNotRaft(note, err);
    BOOST_CHECK(!result.clustered);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_cluster_is_not_cluster)
{
    modelnet::SwarmNotRaft note = NotedNote();
    note.want_cluster = true;
    std::string err = "prior";
    const modelnet::SwarmNotRaftResult result = modelnet::SwarmNoteNotRaft(note, err);
    BOOST_CHECK(!result.clustered);
    BOOST_CHECK_EQUAL(result.code, "NOT_CLUSTER");
    BOOST_CHECK_EQUAL(err, "NOT_CLUSTER");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotRaft note = NotedNote();
    note.want_cluster = false;
    std::string err = "prior";
    const modelnet::SwarmNotRaftResult result = modelnet::SwarmNoteNotRaft(note, err);
    BOOST_CHECK(!result.clustered);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
