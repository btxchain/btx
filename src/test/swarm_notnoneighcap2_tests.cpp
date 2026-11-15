// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoneighcap2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoneighcap2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmNotNoNeighCap2 note;
    note.node_id.clear();
    note.low_rtt = 5;
    note.extra_domains = 3;
    note.want_raise = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoNeighCap2Result result = modelnet::SwarmNoteNotNoNeighCap2(note, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(low_rtt_above_4_is_capped)
{
    modelnet::SwarmNotNoNeighCap2 note;
    note.node_id = "node-1";
    note.low_rtt = 5;
    note.extra_domains = 2;
    note.want_raise = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoNeighCap2Result result = modelnet::SwarmNoteNotNoNeighCap2(note, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(want_raise_at_4_and_2_is_capped)
{
    modelnet::SwarmNotNoNeighCap2 note;
    note.node_id = "node-1";
    note.low_rtt = 4;
    note.extra_domains = 2;
    note.want_raise = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoNeighCap2Result result = modelnet::SwarmNoteNotNoNeighCap2(note, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(plain_4_and_2_is_noted)
{
    modelnet::SwarmNotNoNeighCap2 note;
    note.node_id = "node-1";
    note.low_rtt = 4;
    note.extra_domains = 2;
    note.want_raise = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoNeighCap2Result result = modelnet::SwarmNoteNotNoNeighCap2(note, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
