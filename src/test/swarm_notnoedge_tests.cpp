// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoedge.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoedge_tests, BasicTestingSetup)

static modelnet::SwarmNotNoEdge NotedNote()
{
    modelnet::SwarmNotNoEdge note;
    note.edge_id = "edge-1";
    note.first_edge = false;
    note.want_add_fee = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_edge_id)
{
    modelnet::SwarmNotNoEdge note = NotedNote();
    note.edge_id.clear();
    note.first_edge = true;
    note.want_add_fee = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoEdgeResult result = modelnet::SwarmNoteNotNoEdge(note, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "EDGE");
    BOOST_CHECK_EQUAL(err, "EDGE");
}

BOOST_AUTO_TEST_CASE(first_edge)
{
    modelnet::SwarmNotNoEdge note = NotedNote();
    note.first_edge = true;
    note.want_add_fee = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoEdgeResult result = modelnet::SwarmNoteNotNoEdge(note, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_ADDED");
    BOOST_CHECK_EQUAL(err, "NOT_ADDED");
}

BOOST_AUTO_TEST_CASE(want_add_fee_on_later_edge)
{
    modelnet::SwarmNotNoEdge note = NotedNote();
    note.edge_id = "edge-2";
    note.first_edge = false;
    note.want_add_fee = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoEdgeResult result = modelnet::SwarmNoteNotNoEdge(note, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_ADDED");
    BOOST_CHECK_EQUAL(err, "NOT_ADDED");
}

BOOST_AUTO_TEST_CASE(plain_later_edge)
{
    modelnet::SwarmNotNoEdge note = NotedNote();
    note.edge_id = "edge-2";
    note.first_edge = false;
    note.want_add_fee = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoEdgeResult result = modelnet::SwarmNoteNotNoEdge(note, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
