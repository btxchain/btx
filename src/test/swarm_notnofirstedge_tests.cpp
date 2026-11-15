// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofirstedge.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnofirstedge_tests, BasicTestingSetup)

static modelnet::SwarmNotNoFirstEdge NotedNote()
{
    modelnet::SwarmNotNoFirstEdge note;
    note.edge_id = "edge-1";
    note.first_edge = false;
    note.want_charge = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty)
{
    modelnet::SwarmNotNoFirstEdge note = NotedNote();
    note.edge_id.clear();
    note.first_edge = true;
    note.want_charge = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFirstEdgeResult result = modelnet::SwarmNoteNotNoFirstEdge(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "EDGE");
    BOOST_CHECK_EQUAL(err, "EDGE");
}

BOOST_AUTO_TEST_CASE(first_edge)
{
    modelnet::SwarmNotNoFirstEdge note = NotedNote();
    note.first_edge = true;
    note.want_charge = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFirstEdgeResult result = modelnet::SwarmNoteNotNoFirstEdge(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_CHARGED");
    BOOST_CHECK_EQUAL(err, "NOT_CHARGED");
}

BOOST_AUTO_TEST_CASE(want_charge_on_later_edge)
{
    modelnet::SwarmNotNoFirstEdge note = NotedNote();
    note.edge_id = "edge-2";
    note.first_edge = false;
    note.want_charge = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFirstEdgeResult result = modelnet::SwarmNoteNotNoFirstEdge(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_CHARGED");
    BOOST_CHECK_EQUAL(err, "NOT_CHARGED");
}

BOOST_AUTO_TEST_CASE(plain_later_edge)
{
    modelnet::SwarmNotNoFirstEdge note = NotedNote();
    note.edge_id = "edge-2";
    note.first_edge = false;
    note.want_charge = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFirstEdgeResult result = modelnet::SwarmNoteNotNoFirstEdge(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
