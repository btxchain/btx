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

BOOST_FIXTURE_TEST_SUITE(swarm_agentexec_deny_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(no_prefix_is_denied_and_does_not_set_ran)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(!exec.Execute("sha256", "weights/blob", "body", err));
    BOOST_REQUIRE(err == "DENIED");
    BOOST_REQUIRE(!exec.ran());
    BOOST_REQUIRE(exec.result().empty());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(a_path_outside_the_prefix_is_denied)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(!exec.Execute("sha256", "models/blob", "body", err));
    BOOST_REQUIRE(err == "DENIED");
    BOOST_REQUIRE(!exec.ran());
    BOOST_REQUIRE(exec.result().empty());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(a_shorter_path_does_not_begin_with_the_prefix)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(!exec.Execute("sha256", "weights", "body", err));
    BOOST_REQUIRE(err == "DENIED");
    BOOST_REQUIRE(!exec.Execute("sha256", "weight", "body", err));
    BOOST_REQUIRE(err == "DENIED");
    BOOST_REQUIRE(!exec.ran());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(an_empty_path_is_denied)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(!exec.Execute("sha256", "", "body", err));
    BOOST_REQUIRE(err == "DENIED");
    BOOST_REQUIRE(!exec.ran());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(empty_tool_is_tool_before_the_path_check)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(!exec.Execute("", "weights/blob", "body", err));
    BOOST_REQUIRE(err == "TOOL");
    BOOST_REQUIRE(!exec.Execute("", "missing/blob", "body", err));
    BOOST_REQUIRE(err == "TOOL");
    BOOST_REQUIRE(!exec.Execute("", "private/ledger", "body", err));
    BOOST_REQUIRE(err == "TOOL");
    BOOST_REQUIRE(!exec.ran());
    BOOST_REQUIRE(exec.result().empty());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(another_tool_name_is_tool)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(!exec.Execute("read", "weights/blob", "body", err));
    BOOST_REQUIRE(err == "TOOL");
    BOOST_REQUIRE(!exec.Execute("SHA256", "weights/blob", "body", err));
    BOOST_REQUIRE(err == "TOOL");
    BOOST_REQUIRE(!exec.Execute("sha256 ", "weights/blob", "body", err));
    BOOST_REQUIRE(err == "TOOL");
    BOOST_REQUIRE(!exec.ran());
    BOOST_REQUIRE(exec.result().empty());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(empty_payload_on_another_tool_is_payload)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(!exec.Execute("read", "weights/blob", "", err));
    BOOST_REQUIRE(err == "PAYLOAD");
    BOOST_REQUIRE(!exec.ran());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(denied_does_not_clear_a_stored_digest)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(exec.Execute("sha256", "weights/blob", "body", err));
    BOOST_REQUIRE(exec.ran());
    const std::string digest = exec.result();
    BOOST_REQUIRE(!digest.empty());

    BOOST_REQUIRE(!exec.Execute("sha256", "models/blob", "other", err));
    BOOST_REQUIRE(err == "DENIED");
    BOOST_REQUIRE(exec.ran());
    BOOST_REQUIRE(exec.result() == digest);
    BOOST_REQUIRE(!exec.Execute("read", "weights/blob", "other", err));
    BOOST_REQUIRE(err == "TOOL");
    BOOST_REQUIRE(exec.result() == digest);
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(a_private_path_outside_every_prefix_is_denied)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(!exec.Execute("sha256", "private/ledger", "body", err));
    BOOST_REQUIRE(err == "DENIED");
    BOOST_REQUIRE(!exec.ran());
    BOOST_REQUIRE(exec.result().empty());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_SUITE_END()
