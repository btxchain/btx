// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofallconn2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnofallconn2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_peer_id_is_peer)
{
    modelnet::SwarmNotNoFallConn2 note;
    std::string err = "prior";
    const modelnet::SwarmNotNoFallConn2Result result = modelnet::SwarmNoteNotNoFallConn2(note, err);
    BOOST_CHECK_EQUAL(result.connected, false);
    BOOST_CHECK_EQUAL(result.code, "PEER");
    BOOST_CHECK_EQUAL(err, "PEER");
}

BOOST_AUTO_TEST_CASE(fallback_true_want_connect_false_is_not_connected)
{
    modelnet::SwarmNotNoFallConn2 note;
    note.peer_id = "peer";
    note.fallback = true;
    note.want_connect = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFallConn2Result result = modelnet::SwarmNoteNotNoFallConn2(note, err);
    BOOST_CHECK_EQUAL(result.connected, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_CONNECTED");
    BOOST_CHECK_EQUAL(err, "NOT_CONNECTED");
}

BOOST_AUTO_TEST_CASE(want_connect_true_fallback_false_is_held)
{
    modelnet::SwarmNotNoFallConn2 note;
    note.peer_id = "peer";
    note.fallback = false;
    note.want_connect = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFallConn2Result result = modelnet::SwarmNoteNotNoFallConn2(note, err);
    BOOST_CHECK_EQUAL(result.connected, false);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(neither_is_noted)
{
    modelnet::SwarmNotNoFallConn2 note;
    note.peer_id = "peer";
    note.fallback = false;
    note.want_connect = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFallConn2Result result = modelnet::SwarmNoteNotNoFallConn2(note, err);
    BOOST_CHECK_EQUAL(result.connected, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
