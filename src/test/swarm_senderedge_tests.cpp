// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_senderedge.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_senderedge_tests, BasicTestingSetup)

static modelnet::SwarmSenderEdge NotedEdge()
{
    modelnet::SwarmSenderEdge edge;
    edge.invoice_id = "inv-a";
    edge.hop = 1;
    edge.sender_owned = true;
    edge.want_fee = false;
    edge.want_cltv = false;
    return edge;
}

BOOST_AUTO_TEST_CASE(empty_invoice_id_is_edge)
{
    modelnet::SwarmSenderEdge edge = NotedEdge();
    edge.invoice_id.clear();
    std::string err = "prior";
    const modelnet::SwarmSenderEdgeResult result = modelnet::SwarmNoteSenderEdge(edge, err);
    BOOST_CHECK_EQUAL(result.fee_atoms, 0);
    BOOST_CHECK(!result.cltv_added);
    BOOST_CHECK_EQUAL(result.code, "EDGE");
    BOOST_CHECK_EQUAL(err, "EDGE");
}

BOOST_AUTO_TEST_CASE(empty_invoice_id_wins_over_want_fee_and_want_cltv)
{
    modelnet::SwarmSenderEdge edge = NotedEdge();
    edge.invoice_id.clear();
    edge.want_fee = true;
    edge.want_cltv = true;
    std::string err = "prior";
    const modelnet::SwarmSenderEdgeResult result = modelnet::SwarmNoteSenderEdge(edge, err);
    BOOST_CHECK_EQUAL(result.fee_atoms, 0);
    BOOST_CHECK(!result.cltv_added);
    BOOST_CHECK_EQUAL(result.code, "EDGE");
    BOOST_CHECK_EQUAL(err, "EDGE");
}

BOOST_AUTO_TEST_CASE(hop_below_one_is_edge)
{
    modelnet::SwarmSenderEdge edge = NotedEdge();
    edge.hop = 0;
    std::string err = "prior";
    const modelnet::SwarmSenderEdgeResult result = modelnet::SwarmNoteSenderEdge(edge, err);
    BOOST_CHECK_EQUAL(result.fee_atoms, 0);
    BOOST_CHECK(!result.cltv_added);
    BOOST_CHECK_EQUAL(result.code, "EDGE");
    BOOST_CHECK_EQUAL(err, "EDGE");
}

BOOST_AUTO_TEST_CASE(negative_hop_is_edge)
{
    modelnet::SwarmSenderEdge edge = NotedEdge();
    edge.hop = -1;
    edge.want_fee = true;
    edge.want_cltv = true;
    std::string err = "prior";
    const modelnet::SwarmSenderEdgeResult result = modelnet::SwarmNoteSenderEdge(edge, err);
    BOOST_CHECK_EQUAL(result.fee_atoms, 0);
    BOOST_CHECK(!result.cltv_added);
    BOOST_CHECK_EQUAL(result.code, "EDGE");
    BOOST_CHECK_EQUAL(err, "EDGE");
}

BOOST_AUTO_TEST_CASE(hop_not_one_is_not_first)
{
    modelnet::SwarmSenderEdge edge = NotedEdge();
    edge.hop = 2;
    std::string err = "prior";
    const modelnet::SwarmSenderEdgeResult result = modelnet::SwarmNoteSenderEdge(edge, err);
    BOOST_CHECK_EQUAL(result.fee_atoms, 0);
    BOOST_CHECK(!result.cltv_added);
    BOOST_CHECK_EQUAL(result.code, "NOT_FIRST");
    BOOST_CHECK_EQUAL(err, "NOT_FIRST");
}

BOOST_AUTO_TEST_CASE(hop_not_one_wins_over_want_fee_and_want_cltv)
{
    modelnet::SwarmSenderEdge edge = NotedEdge();
    edge.hop = 2;
    edge.want_fee = true;
    edge.want_cltv = true;
    std::string err = "prior";
    const modelnet::SwarmSenderEdgeResult result = modelnet::SwarmNoteSenderEdge(edge, err);
    BOOST_CHECK_EQUAL(result.fee_atoms, 0);
    BOOST_CHECK(!result.cltv_added);
    BOOST_CHECK_EQUAL(result.code, "NOT_FIRST");
    BOOST_CHECK_EQUAL(err, "NOT_FIRST");
}

BOOST_AUTO_TEST_CASE(not_sender_owned_is_not_first)
{
    modelnet::SwarmSenderEdge edge = NotedEdge();
    edge.sender_owned = false;
    std::string err = "prior";
    const modelnet::SwarmSenderEdgeResult result = modelnet::SwarmNoteSenderEdge(edge, err);
    BOOST_CHECK_EQUAL(result.fee_atoms, 0);
    BOOST_CHECK(!result.cltv_added);
    BOOST_CHECK_EQUAL(result.code, "NOT_FIRST");
    BOOST_CHECK_EQUAL(err, "NOT_FIRST");
}

BOOST_AUTO_TEST_CASE(not_sender_owned_wins_over_want_fee_and_want_cltv)
{
    modelnet::SwarmSenderEdge edge = NotedEdge();
    edge.sender_owned = false;
    edge.want_fee = true;
    edge.want_cltv = true;
    std::string err = "prior";
    const modelnet::SwarmSenderEdgeResult result = modelnet::SwarmNoteSenderEdge(edge, err);
    BOOST_CHECK_EQUAL(result.fee_atoms, 0);
    BOOST_CHECK(!result.cltv_added);
    BOOST_CHECK_EQUAL(result.code, "NOT_FIRST");
    BOOST_CHECK_EQUAL(err, "NOT_FIRST");
}

BOOST_AUTO_TEST_CASE(want_fee_is_no_fee)
{
    modelnet::SwarmSenderEdge edge = NotedEdge();
    edge.want_fee = true;
    std::string err = "prior";
    const modelnet::SwarmSenderEdgeResult result = modelnet::SwarmNoteSenderEdge(edge, err);
    BOOST_CHECK_EQUAL(result.fee_atoms, 0);
    BOOST_CHECK(!result.cltv_added);
    BOOST_CHECK_EQUAL(result.code, "NO_FEE");
    BOOST_CHECK_EQUAL(err, "NO_FEE");
}

BOOST_AUTO_TEST_CASE(want_fee_wins_over_want_cltv)
{
    modelnet::SwarmSenderEdge edge = NotedEdge();
    edge.want_fee = true;
    edge.want_cltv = true;
    std::string err = "prior";
    const modelnet::SwarmSenderEdgeResult result = modelnet::SwarmNoteSenderEdge(edge, err);
    BOOST_CHECK_EQUAL(result.fee_atoms, 0);
    BOOST_CHECK(!result.cltv_added);
    BOOST_CHECK_EQUAL(result.code, "NO_FEE");
    BOOST_CHECK_EQUAL(err, "NO_FEE");
}

BOOST_AUTO_TEST_CASE(want_cltv_is_no_cltv)
{
    modelnet::SwarmSenderEdge edge = NotedEdge();
    edge.want_cltv = true;
    std::string err = "prior";
    const modelnet::SwarmSenderEdgeResult result = modelnet::SwarmNoteSenderEdge(edge, err);
    BOOST_CHECK_EQUAL(result.fee_atoms, 0);
    BOOST_CHECK(!result.cltv_added);
    BOOST_CHECK_EQUAL(result.code, "NO_CLTV");
    BOOST_CHECK_EQUAL(err, "NO_CLTV");
}

BOOST_AUTO_TEST_CASE(sender_first_edge_is_noted)
{
    modelnet::SwarmSenderEdge edge = NotedEdge();
    std::string err = "prior";
    const modelnet::SwarmSenderEdgeResult result = modelnet::SwarmNoteSenderEdge(edge, err);
    BOOST_CHECK_EQUAL(result.fee_atoms, 0);
    BOOST_CHECK(!result.cltv_added);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
