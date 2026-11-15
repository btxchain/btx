// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoneigh.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoneigh_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmNotNoNeigh note;
    note.node_id.clear();
    note.lowest_rtt = 5;
    note.new_domains = 3;
    note.want_connect = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoNeighResult result = modelnet::SwarmNoteNotNoNeigh(note, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK_EQUAL(result.applied, 0);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(lowest_rtt_above_4_is_capped)
{
    modelnet::SwarmNotNoNeigh note;
    note.node_id = "node-1";
    note.lowest_rtt = 5;
    note.new_domains = 2;
    note.want_connect = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoNeighResult result = modelnet::SwarmNoteNotNoNeigh(note, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK_EQUAL(result.applied, 0);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(want_connect_at_4_and_2_is_capped)
{
    modelnet::SwarmNotNoNeigh note;
    note.node_id = "node-1";
    note.lowest_rtt = 4;
    note.new_domains = 2;
    note.want_connect = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoNeighResult result = modelnet::SwarmNoteNotNoNeigh(note, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK_EQUAL(result.applied, 0);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(plain_4_and_2_is_noted)
{
    modelnet::SwarmNotNoNeigh note;
    note.node_id = "node-1";
    note.lowest_rtt = 4;
    note.new_domains = 2;
    note.want_connect = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoNeighResult result = modelnet::SwarmNoteNotNoNeigh(note, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK_EQUAL(result.applied, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
