// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_peerpath.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_peerpath_tests, BasicTestingSetup)

static modelnet::SwarmPeerPath NotedPath()
{
    modelnet::SwarmPeerPath path;
    path.peer_id = "peer-a";
    path.relative_path = "piece.bin";
    path.want_open = false;
    return path;
}

static void ExpectOpenedStaysFalse(const modelnet::SwarmPeerPathResult& result)
{
    BOOST_CHECK(!result.opened);
}

BOOST_AUTO_TEST_CASE(empty_peer_id_is_path)
{
    modelnet::SwarmPeerPath path = NotedPath();
    path.peer_id.clear();
    std::string err = "prior";
    const modelnet::SwarmPeerPathResult result = modelnet::SwarmNotePeerPath(path, err);
    ExpectOpenedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "PATH");
    BOOST_CHECK_EQUAL(err, "PATH");
}

BOOST_AUTO_TEST_CASE(empty_relative_path_is_path)
{
    modelnet::SwarmPeerPath path = NotedPath();
    path.relative_path.clear();
    std::string err = "prior";
    const modelnet::SwarmPeerPathResult result = modelnet::SwarmNotePeerPath(path, err);
    ExpectOpenedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "PATH");
    BOOST_CHECK_EQUAL(err, "PATH");
}

BOOST_AUTO_TEST_CASE(empty_peer_id_wins_over_peer_path_and_want_open)
{
    modelnet::SwarmPeerPath path = NotedPath();
    path.peer_id.clear();
    path.relative_path = "..";
    path.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmPeerPathResult result = modelnet::SwarmNotePeerPath(path, err);
    ExpectOpenedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "PATH");
    BOOST_CHECK_EQUAL(err, "PATH");
}

BOOST_AUTO_TEST_CASE(empty_relative_path_wins_over_want_open)
{
    modelnet::SwarmPeerPath path = NotedPath();
    path.relative_path.clear();
    path.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmPeerPathResult result = modelnet::SwarmNotePeerPath(path, err);
    ExpectOpenedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "PATH");
    BOOST_CHECK_EQUAL(err, "PATH");
}

BOOST_AUTO_TEST_CASE(slash_is_peer_path)
{
    modelnet::SwarmPeerPath path = NotedPath();
    path.relative_path = "sub/piece.bin";
    path.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmPeerPathResult result = modelnet::SwarmNotePeerPath(path, err);
    ExpectOpenedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "PEER_PATH");
    BOOST_CHECK_EQUAL(err, "PEER_PATH");
}

BOOST_AUTO_TEST_CASE(backslash_is_peer_path)
{
    modelnet::SwarmPeerPath path = NotedPath();
    path.relative_path = "sub\\piece.bin";
    path.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmPeerPathResult result = modelnet::SwarmNotePeerPath(path, err);
    ExpectOpenedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "PEER_PATH");
    BOOST_CHECK_EQUAL(err, "PEER_PATH");
}

BOOST_AUTO_TEST_CASE(dot_dot_segment_is_peer_path)
{
    modelnet::SwarmPeerPath path = NotedPath();
    path.relative_path = "..";
    path.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmPeerPathResult result = modelnet::SwarmNotePeerPath(path, err);
    ExpectOpenedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "PEER_PATH");
    BOOST_CHECK_EQUAL(err, "PEER_PATH");
}

BOOST_AUTO_TEST_CASE(peer_path_wins_when_want_open_is_true)
{
    modelnet::SwarmPeerPath path = NotedPath();
    path.relative_path = "sub/piece.bin";
    path.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmPeerPathResult result = modelnet::SwarmNotePeerPath(path, err);
    ExpectOpenedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "PEER_PATH");
    BOOST_CHECK_EQUAL(err, "PEER_PATH");
}

BOOST_AUTO_TEST_CASE(want_open_is_held)
{
    modelnet::SwarmPeerPath path = NotedPath();
    path.relative_path = "piece.bin";
    path.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmPeerPathResult result = modelnet::SwarmNotePeerPath(path, err);
    ExpectOpenedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(single_token_is_noted)
{
    modelnet::SwarmPeerPath path = NotedPath();
    std::string err = "prior";
    const modelnet::SwarmPeerPathResult result = modelnet::SwarmNotePeerPath(path, err);
    ExpectOpenedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
