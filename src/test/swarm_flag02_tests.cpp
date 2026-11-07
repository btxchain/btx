// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag02.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_flag02_tests, BasicTestingSetup)

static modelnet::SwarmFlag02 NotedJoin()
{
    modelnet::SwarmFlag02 in;
    in.family_id = "family-1";
    in.peer_id = "peer-1";
    in.manual_config = false;
    in.want_connect = false;
    in.want_pass = false;
    return in;
}

static void ExpectStill(const modelnet::SwarmFlag02Result& result)
{
    BOOST_CHECK_EQUAL(result.joined, false);
    BOOST_CHECK_EQUAL(result.connected, false);
    BOOST_CHECK_EQUAL(result.traversed, false);
    BOOST_CHECK_EQUAL(result.passed, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
}

BOOST_AUTO_TEST_CASE(empty_family_id_is_family)
{
    modelnet::SwarmFlag02 in = NotedJoin();
    in.family_id.clear();
    in.manual_config = true;
    in.want_connect = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag02Result result = modelnet::SwarmStageJoin(in, err);
    ExpectStill(result);
    BOOST_CHECK_EQUAL(result.code, "FAMILY");
    BOOST_CHECK_EQUAL(err, "FAMILY");
}

BOOST_AUTO_TEST_CASE(empty_peer_id_is_family)
{
    modelnet::SwarmFlag02 in = NotedJoin();
    in.peer_id.clear();
    in.manual_config = true;
    in.want_connect = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag02Result result = modelnet::SwarmStageJoin(in, err);
    ExpectStill(result);
    BOOST_CHECK_EQUAL(result.code, "FAMILY");
    BOOST_CHECK_EQUAL(err, "FAMILY");
}

BOOST_AUTO_TEST_CASE(manual_config_is_manual)
{
    modelnet::SwarmFlag02 in = NotedJoin();
    in.manual_config = true;
    in.want_connect = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag02Result result = modelnet::SwarmStageJoin(in, err);
    ExpectStill(result);
    BOOST_CHECK_EQUAL(result.code, "MANUAL");
    BOOST_CHECK_EQUAL(err, "MANUAL");
}

BOOST_AUTO_TEST_CASE(want_connect_is_no_socket)
{
    modelnet::SwarmFlag02 in = NotedJoin();
    in.want_connect = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag02Result result = modelnet::SwarmStageJoin(in, err);
    ExpectStill(result);
    BOOST_CHECK_EQUAL(result.code, "NO_SOCKET");
    BOOST_CHECK_EQUAL(err, "NO_SOCKET");
}

BOOST_AUTO_TEST_CASE(want_pass_is_unqualified)
{
    modelnet::SwarmFlag02 in = NotedJoin();
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag02Result result = modelnet::SwarmStageJoin(in, err);
    ExpectStill(result);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(plain_join_is_noted)
{
    modelnet::SwarmFlag02 in = NotedJoin();
    std::string err = "prior";
    const modelnet::SwarmFlag02Result result = modelnet::SwarmStageJoin(in, err);
    ExpectStill(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
