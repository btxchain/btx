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

BOOST_FIXTURE_TEST_SUITE(swarm_agentexec_allow_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_prefix_is_path_and_stores_nothing)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(!exec.Allow("", err));
    BOOST_REQUIRE(err == "PATH");
    BOOST_REQUIRE(!exec.ran());
    BOOST_REQUIRE(exec.result().empty());

    BOOST_REQUIRE(!exec.Execute("sha256", "weights/blob", "body", err));
    BOOST_REQUIRE(err == "DENIED");
    BOOST_REQUIRE(!exec.ran());
    BOOST_REQUIRE(exec.result().empty());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(empty_prefix_after_a_stored_prefix_leaves_the_first)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!exec.Allow("", err));
    BOOST_REQUIRE(err == "PATH");

    BOOST_REQUIRE(exec.Execute("sha256", "weights/blob", "body", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(exec.ran());
    BOOST_REQUIRE(!exec.result().empty());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(non_empty_prefix_is_stored)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(exec.Execute("sha256", "weights/blob", "body", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(exec.ran());
    BOOST_REQUIRE(!exec.launched());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(a_second_identical_prefix_is_replay)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!exec.Allow("weights/", err));
    BOOST_REQUIRE(err == "REPLAY");

    BOOST_REQUIRE(exec.Execute("sha256", "weights/blob", "body", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(exec.ran());
    const std::string first = exec.result();

    BOOST_REQUIRE(!exec.Allow("weights/", err));
    BOOST_REQUIRE(err == "REPLAY");
    BOOST_REQUIRE(exec.result() == first);
    BOOST_REQUIRE(exec.ran());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(a_different_prefix_is_stored_beside_the_first)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(exec.Allow("models/", err));
    BOOST_REQUIRE(err.empty());

    BOOST_REQUIRE(exec.Execute("sha256", "weights/a", "one", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(exec.Execute("sha256", "models/b", "two", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(exec.ran());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(a_prefix_of_another_prefix_is_not_replay)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("ab", err));
    BOOST_REQUIRE(exec.Allow("abc", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!exec.Allow("ab", err));
    BOOST_REQUIRE(err == "REPLAY");
    BOOST_REQUIRE(!exec.Allow("abc", err));
    BOOST_REQUIRE(err == "REPLAY");

    BOOST_REQUIRE(exec.Execute("sha256", "abcd", "body", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(exec.ran());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(path_equal_to_the_prefix_begins_with_it)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("weights", err));
    BOOST_REQUIRE(exec.Execute("sha256", "weights", "body", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(exec.ran());
    BOOST_REQUIRE(exec.Execute("sha256", "weights/extra", "body-2", err));
    BOOST_REQUIRE(err.empty());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(allow_does_not_launch_or_connect)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(!exec.ran());
    BOOST_REQUIRE(exec.result().empty());
    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(!exec.ran());
    BOOST_REQUIRE(exec.result().empty());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_SUITE_END()
