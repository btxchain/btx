// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentproto.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_agentproto_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_protocol_is_protocol)
{
    modelnet::SwarmAgentMessage message;
    message.protocol = "";
    message.method = "tools/list";
    std::string err;
    const modelnet::SwarmAgentAdmit result = modelnet::SwarmAdmitAgentMessage(message, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.executed);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "PROTOCOL");
    BOOST_CHECK_EQUAL(err, "PROTOCOL");
}

BOOST_AUTO_TEST_CASE(unknown_protocol_is_protocol)
{
    modelnet::SwarmAgentMessage message;
    message.protocol = "grpc";
    message.method = "tools/list";
    std::string err;
    const modelnet::SwarmAgentAdmit result = modelnet::SwarmAdmitAgentMessage(message, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.executed);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "PROTOCOL");
    BOOST_CHECK_EQUAL(err, "PROTOCOL");
}

BOOST_AUTO_TEST_CASE(executable_payload_is_code_refused)
{
    modelnet::SwarmAgentMessage message;
    message.protocol = "mcp";
    message.method = "tools/call";
    message.carries_executable = true;
    std::string err;
    const modelnet::SwarmAgentAdmit result = modelnet::SwarmAdmitAgentMessage(message, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.executed);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "CODE_REFUSED");
    BOOST_CHECK_EQUAL(err, "CODE_REFUSED");
}

BOOST_AUTO_TEST_CASE(proprietary_framework_is_framework)
{
    modelnet::SwarmAgentMessage message;
    message.protocol = "a2a";
    message.method = "message/send";
    message.proprietary_framework_required = true;
    std::string err;
    const modelnet::SwarmAgentAdmit result = modelnet::SwarmAdmitAgentMessage(message, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.executed);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "FRAMEWORK");
    BOOST_CHECK_EQUAL(err, "FRAMEWORK");
}

BOOST_AUTO_TEST_CASE(mcp_method_is_ok_and_not_executed)
{
    modelnet::SwarmAgentMessage message;
    message.protocol = "mcp";
    message.method = "tools/list";
    std::string err = "prior";
    const modelnet::SwarmAgentAdmit result = modelnet::SwarmAdmitAgentMessage(message, err);
    BOOST_CHECK(result.admitted);
    BOOST_CHECK(!result.executed);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "OK");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(a2a_method_is_ok_and_not_executed)
{
    modelnet::SwarmAgentMessage message;
    message.protocol = "a2a";
    message.method = "message/send";
    std::string err = "prior";
    const modelnet::SwarmAgentAdmit result = modelnet::SwarmAdmitAgentMessage(message, err);
    BOOST_CHECK(result.admitted);
    BOOST_CHECK(!result.executed);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK_EQUAL(result.code, "OK");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
