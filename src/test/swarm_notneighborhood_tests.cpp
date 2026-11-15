// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notneighborhood.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notneighborhood_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id)
{
    modelnet::SwarmNotNeighborhood note;
    std::string err = "stale";
    const modelnet::SwarmNotNeighborhoodResult result = modelnet::SwarmNoteNotNeighborhood(note, err);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK(!result.connected);
    BOOST_CHECK_EQUAL(result.chosen, 0);
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(peer_count_7)
{
    modelnet::SwarmNotNeighborhood note;
    note.node_id = "node-1";
    note.peer_count = 7;
    note.want_connect = false;
    std::string err = "stale";
    const modelnet::SwarmNotNeighborhoodResult result = modelnet::SwarmNoteNotNeighborhood(note, err);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK(!result.connected);
    BOOST_CHECK_EQUAL(result.chosen, 0);
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(want_connect_peer_count_1)
{
    modelnet::SwarmNotNeighborhood note;
    note.node_id = "node-1";
    note.peer_count = 1;
    note.want_connect = true;
    std::string err = "stale";
    const modelnet::SwarmNotNeighborhoodResult result = modelnet::SwarmNoteNotNeighborhood(note, err);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK(!result.connected);
    BOOST_CHECK_EQUAL(result.chosen, 0);
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(plain_note_peer_count_4)
{
    modelnet::SwarmNotNeighborhood note;
    note.node_id = "node-1";
    note.peer_count = 4;
    note.want_connect = false;
    std::string err = "stale";
    const modelnet::SwarmNotNeighborhoodResult result = modelnet::SwarmNoteNotNeighborhood(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.connected);
    BOOST_CHECK_EQUAL(result.chosen, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
