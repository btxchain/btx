// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_passthru.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_passthru_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node)
{
    modelnet::SwarmPassthru node;
    node.node_id.clear();
    node.want_start = false;
    std::string err;
    const modelnet::SwarmPassthruResult result = modelnet::SwarmNotePassthru(node, err);
    BOOST_CHECK(!result.started);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_start_true)
{
    modelnet::SwarmPassthru node;
    node.node_id = "n1";
    node.want_start = true;
    std::string err;
    const modelnet::SwarmPassthruResult result = modelnet::SwarmNotePassthru(node, err);
    BOOST_CHECK(!result.started);
    BOOST_CHECK_EQUAL(result.code, "NOT_STARTED");
    BOOST_CHECK_EQUAL(err, "NOT_STARTED");
}

BOOST_AUTO_TEST_CASE(want_start_false)
{
    modelnet::SwarmPassthru node;
    node.node_id = "n2";
    node.want_start = false;
    std::string err = "stale";
    const modelnet::SwarmPassthruResult result = modelnet::SwarmNotePassthru(node, err);
    BOOST_CHECK(!result.started);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
