// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_firstedge.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_firstedge_tests, BasicTestingSetup)

static modelnet::SwarmFirstEdge NotedEdge()
{
    modelnet::SwarmFirstEdge edge;
    edge.edge_id = "edge-1";
    edge.first_edge = false;
    edge.want_charge = false;
    return edge;
}

BOOST_AUTO_TEST_CASE(empty_edge_is_edge)
{
    modelnet::SwarmFirstEdge edge = NotedEdge();
    edge.edge_id.clear();
    std::string err = "prior";
    const modelnet::SwarmFirstEdgeResult result = modelnet::SwarmNoteFirstEdgeFee(edge, err);
    BOOST_CHECK_EQUAL(result.code, "EDGE");
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "EDGE");
}

BOOST_AUTO_TEST_CASE(first_edge_is_no_fee)
{
    modelnet::SwarmFirstEdge edge = NotedEdge();
    edge.first_edge = true;
    edge.want_charge = false;
    std::string err = "prior";
    const modelnet::SwarmFirstEdgeResult result = modelnet::SwarmNoteFirstEdgeFee(edge, err);
    BOOST_CHECK_EQUAL(result.code, "NO_FEE");
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "NO_FEE");
}

BOOST_AUTO_TEST_CASE(want_charge_is_held)
{
    modelnet::SwarmFirstEdge edge = NotedEdge();
    edge.want_charge = true;
    edge.first_edge = false;
    std::string err = "prior";
    const modelnet::SwarmFirstEdgeResult result = modelnet::SwarmNoteFirstEdgeFee(edge, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmFirstEdge edge = NotedEdge();
    edge.first_edge = false;
    edge.want_charge = false;
    std::string err = "prior";
    const modelnet::SwarmFirstEdgeResult result = modelnet::SwarmNoteFirstEdgeFee(edge, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
