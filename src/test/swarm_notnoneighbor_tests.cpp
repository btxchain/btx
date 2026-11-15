// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoneighbor.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoneighbor_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty)
{
    modelnet::SwarmNotNoNeighbor note;
    std::string err = "stale";
    const modelnet::SwarmNotNoNeighborResult result = modelnet::SwarmNoteNotNoNeighbor(note, err);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK(!result.expanded);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(low_rtt_3_with_domains_2)
{
    modelnet::SwarmNotNoNeighbor note;
    note.node_id = "node-1";
    note.low_rtt = 3;
    note.new_domains = 2;
    note.want_expand = false;
    std::string err = "stale";
    const modelnet::SwarmNotNoNeighborResult result = modelnet::SwarmNoteNotNoNeighbor(note, err);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK(!result.expanded);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(low_rtt_4_with_domains_1)
{
    modelnet::SwarmNotNoNeighbor note;
    note.node_id = "node-1";
    note.low_rtt = 4;
    note.new_domains = 1;
    note.want_expand = false;
    std::string err = "stale";
    const modelnet::SwarmNotNoNeighborResult result = modelnet::SwarmNoteNotNoNeighbor(note, err);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK(!result.expanded);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(exact_counts_with_want_expand)
{
    modelnet::SwarmNotNoNeighbor note;
    note.node_id = "node-1";
    note.low_rtt = 4;
    note.new_domains = 2;
    note.want_expand = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoNeighborResult result = modelnet::SwarmNoteNotNoNeighbor(note, err);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK(!result.expanded);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(exact_counts_plain)
{
    modelnet::SwarmNotNoNeighbor note;
    note.node_id = "node-1";
    note.low_rtt = 4;
    note.new_domains = 2;
    note.want_expand = false;
    std::string err = "stale";
    const modelnet::SwarmNotNoNeighborResult result = modelnet::SwarmNoteNotNoNeighbor(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.expanded);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
