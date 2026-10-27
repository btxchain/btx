// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_windowslife.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_windowslife_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmWindowsLife node;
    node.guest_agent = true;
    node.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmWindowsLifeResult result = modelnet::SwarmNoteWindowsLife(node, err);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(missing_guest_agent_is_not_passed)
{
    modelnet::SwarmWindowsLife node;
    node.node_id = "node-1";
    node.guest_agent = false;
    node.want_pass = false;
    std::string err = "prior";
    const modelnet::SwarmWindowsLifeResult result = modelnet::SwarmNoteWindowsLife(node, err);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(result.code, "NOT_PASSED");
    BOOST_CHECK_EQUAL(err, "NOT_PASSED");
}

BOOST_AUTO_TEST_CASE(want_pass_is_held)
{
    modelnet::SwarmWindowsLife node;
    node.node_id = "node-1";
    node.guest_agent = true;
    node.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmWindowsLifeResult result = modelnet::SwarmNoteWindowsLife(node, err);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmWindowsLife node;
    node.node_id = "node-1";
    node.guest_agent = true;
    node.want_pass = false;
    std::string err = "prior";
    const modelnet::SwarmWindowsLifeResult result = modelnet::SwarmNoteWindowsLife(node, err);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
