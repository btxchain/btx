// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandboxcap.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_sandboxcap_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmSandboxCap node;
    node.node_id.clear();
    node.want_raise = false;
    std::string err = "prior";
    const modelnet::SwarmSandboxCapResult result = modelnet::SwarmNoteSandboxCap(node, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_raise_is_capped)
{
    modelnet::SwarmSandboxCap node;
    node.node_id = "node-a";
    node.want_raise = true;
    std::string err = "prior";
    const modelnet::SwarmSandboxCapResult result = modelnet::SwarmNoteSandboxCap(node, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(want_raise_false_is_noted)
{
    modelnet::SwarmSandboxCap node;
    node.node_id = "node-b";
    node.want_raise = false;
    std::string err = "prior";
    const modelnet::SwarmSandboxCapResult result = modelnet::SwarmNoteSandboxCap(node, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
