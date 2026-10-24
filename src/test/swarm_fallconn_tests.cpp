// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fallconn.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fallconn_tests, BasicTestingSetup)

static modelnet::SwarmFallConn NotedPeer()
{
    modelnet::SwarmFallConn peer;
    peer.peer_id = "peer-1";
    peer.fallback = false;
    peer.want_connect = false;
    return peer;
}

BOOST_AUTO_TEST_CASE(empty_peer_id_is_peer)
{
    modelnet::SwarmFallConn peer = NotedPeer();
    peer.peer_id.clear();
    peer.fallback = false;
    peer.want_connect = false;
    std::string err = "prior";
    const modelnet::SwarmFallConnResult result = modelnet::SwarmNoteFallConn(peer, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK_EQUAL(result.code, "PEER");
    BOOST_CHECK_EQUAL(err, "PEER");
}

BOOST_AUTO_TEST_CASE(fallback_true_want_connect_false_is_not_connected)
{
    modelnet::SwarmFallConn peer = NotedPeer();
    peer.fallback = true;
    peer.want_connect = false;
    std::string err = "prior";
    const modelnet::SwarmFallConnResult result = modelnet::SwarmNoteFallConn(peer, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK_EQUAL(result.code, "NOT_CONNECTED");
    BOOST_CHECK_EQUAL(err, "NOT_CONNECTED");
}

BOOST_AUTO_TEST_CASE(want_connect_true_fallback_false_is_held)
{
    modelnet::SwarmFallConn peer = NotedPeer();
    peer.fallback = false;
    peer.want_connect = true;
    std::string err = "prior";
    const modelnet::SwarmFallConnResult result = modelnet::SwarmNoteFallConn(peer, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(fallback_false_want_connect_false_is_noted)
{
    modelnet::SwarmFallConn peer = NotedPeer();
    peer.fallback = false;
    peer.want_connect = false;
    std::string err = "prior";
    const modelnet::SwarmFallConnResult result = modelnet::SwarmNoteFallConn(peer, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
