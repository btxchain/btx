// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentexec/swarm_agentexec.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

void ExpectIdle(const modelnet::SwarmAgentExec& exec)
{
    BOOST_REQUIRE(!exec.launched());
    BOOST_REQUIRE(!exec.connected());
    BOOST_REQUIRE(!exec.gpu());
    BOOST_REQUIRE(!exec.broadcast());
    BOOST_REQUIRE(exec.atoms_moved() == 0);
    BOOST_REQUIRE(exec.automatic_spend() == "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_agentexec_net_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(net_is_denied_and_connected_stays_false)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(!exec.Execute("net", "weights/blob", "body", err));
    BOOST_REQUIRE(err == "NET_DENIED");
    BOOST_REQUIRE(!exec.connected());
    BOOST_REQUIRE(!exec.ran());
    BOOST_REQUIRE(exec.result().empty());
    BOOST_REQUIRE(!exec.launched());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(net_after_allow_does_not_connect)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(!exec.Execute("net", "weights/blob", "body", err));
    BOOST_REQUIRE(err == "NET_DENIED");
    BOOST_REQUIRE(!exec.connected());
    BOOST_REQUIRE(!exec.ran());
    BOOST_REQUIRE(exec.result().empty());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(net_with_an_empty_payload_is_still_net_denied)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(!exec.Execute("net", "weights/blob", "", err));
    BOOST_REQUIRE(err == "NET_DENIED");
    BOOST_REQUIRE(!exec.connected());
    BOOST_REQUIRE(!exec.ran());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(net_on_a_private_path_does_not_connect)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("private/", err));
    BOOST_REQUIRE(!exec.Execute("net", "private/ledger", "body", err));
    BOOST_REQUIRE(err == "NET_DENIED");
    BOOST_REQUIRE(!exec.connected());
    BOOST_REQUIRE(!exec.ran());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(net_on_a_denied_path_does_not_connect)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(!exec.Execute("net", "models/blob", "body", err));
    BOOST_REQUIRE(err == "NET_DENIED");
    BOOST_REQUIRE(!exec.connected());
    BOOST_REQUIRE(!exec.ran());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(net_after_a_digest_keeps_the_digest_and_stays_unconnected)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(exec.Execute("sha256", "weights/blob", "body", err));
    BOOST_REQUIRE(exec.ran());
    const std::string digest = exec.result();

    BOOST_REQUIRE(!exec.Execute("net", "weights/blob", "body", err));
    BOOST_REQUIRE(err == "NET_DENIED");
    BOOST_REQUIRE(exec.ran());
    BOOST_REQUIRE(exec.result() == digest);
    BOOST_REQUIRE(!exec.connected());
    BOOST_REQUIRE(!exec.launched());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(a_near_tool_name_is_not_net)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(!exec.Execute("Net", "weights/blob", "body", err));
    BOOST_REQUIRE(err == "TOOL");
    BOOST_REQUIRE(!exec.connected());
    BOOST_REQUIRE(!exec.Execute("network", "weights/blob", "body", err));
    BOOST_REQUIRE(err == "TOOL");
    BOOST_REQUIRE(!exec.connected());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_SUITE_END()
