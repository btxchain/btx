// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_firstcltv.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_firstcltv_tests, BasicTestingSetup)

static modelnet::SwarmFirstCltv NotedEdge()
{
    modelnet::SwarmFirstCltv edge;
    edge.edge_id = "edge-1";
    edge.first_edge = false;
    edge.want_add = false;
    return edge;
}

BOOST_AUTO_TEST_CASE(empty_edge_id_is_edge)
{
    modelnet::SwarmFirstCltv edge = NotedEdge();
    edge.edge_id.clear();
    std::string err = "prior";
    const modelnet::SwarmFirstCltvResult result = modelnet::SwarmNoteFirstCltv(edge, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.delay, 0);
    BOOST_CHECK_EQUAL(result.code, "EDGE");
    BOOST_CHECK_EQUAL(err, "EDGE");
}

BOOST_AUTO_TEST_CASE(first_edge_is_not_added)
{
    modelnet::SwarmFirstCltv edge = NotedEdge();
    edge.first_edge = true;
    edge.want_add = false;
    std::string err = "prior";
    const modelnet::SwarmFirstCltvResult result = modelnet::SwarmNoteFirstCltv(edge, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.delay, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_ADDED");
    BOOST_CHECK_EQUAL(err, "NOT_ADDED");
}

BOOST_AUTO_TEST_CASE(want_add_is_held)
{
    modelnet::SwarmFirstCltv edge = NotedEdge();
    edge.first_edge = false;
    edge.want_add = true;
    std::string err = "prior";
    const modelnet::SwarmFirstCltvResult result = modelnet::SwarmNoteFirstCltv(edge, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.delay, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_edge_is_noted)
{
    modelnet::SwarmFirstCltv edge = NotedEdge();
    edge.first_edge = false;
    edge.want_add = false;
    std::string err = "prior";
    const modelnet::SwarmFirstCltvResult result = modelnet::SwarmNoteFirstCltv(edge, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.delay, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
