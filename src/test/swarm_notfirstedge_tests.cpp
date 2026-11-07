// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfirstedge.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notfirstedge_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_edge_id)
{
    modelnet::SwarmNotFirstEdge note;
    note.first_edge = true;
    note.want_fee = true;
    std::string err = "stale";
    const modelnet::SwarmNotFirstEdgeResult out = modelnet::SwarmNoteNotFirstEdge(note, err);
    BOOST_CHECK_EQUAL(out.code, "EDGE");
    BOOST_CHECK(!out.charged);
    BOOST_CHECK_EQUAL(out.cltv_delta, 0);
    BOOST_CHECK_EQUAL(err, "EDGE");
}

BOOST_AUTO_TEST_CASE(first_edge_without_want_fee)
{
    modelnet::SwarmNotFirstEdge note;
    note.edge_id = "edge-1";
    note.first_edge = true;
    note.want_fee = false;
    std::string err = "stale";
    const modelnet::SwarmNotFirstEdgeResult out = modelnet::SwarmNoteNotFirstEdge(note, err);
    BOOST_CHECK_EQUAL(out.code, "NO_FEE");
    BOOST_CHECK(!out.charged);
    BOOST_CHECK_EQUAL(out.cltv_delta, 0);
    BOOST_CHECK_EQUAL(err, "NO_FEE");
}

BOOST_AUTO_TEST_CASE(want_fee_on_later_edge)
{
    modelnet::SwarmNotFirstEdge note;
    note.edge_id = "edge-2";
    note.first_edge = false;
    note.want_fee = true;
    std::string err = "stale";
    const modelnet::SwarmNotFirstEdgeResult out = modelnet::SwarmNoteNotFirstEdge(note, err);
    BOOST_CHECK_EQUAL(out.code, "NOT_CHARGED");
    BOOST_CHECK(!out.charged);
    BOOST_CHECK_EQUAL(out.cltv_delta, 0);
    BOOST_CHECK_EQUAL(err, "NOT_CHARGED");
}

BOOST_AUTO_TEST_CASE(plain_later_edge)
{
    modelnet::SwarmNotFirstEdge note;
    note.edge_id = "edge-2";
    std::string err = "stale";
    const modelnet::SwarmNotFirstEdgeResult out = modelnet::SwarmNoteNotFirstEdge(note, err);
    BOOST_CHECK_EQUAL(out.code, "NOTED");
    BOOST_CHECK(!out.charged);
    BOOST_CHECK_EQUAL(out.cltv_delta, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
