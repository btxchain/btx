// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalrole.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

using modelnet::SwarmEvalRole;
using modelnet::SwarmEvalRoleResult;
using modelnet::SwarmKeepEvaluator;

BOOST_FIXTURE_TEST_SUITE(swarm_evalrole_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    SwarmEvalRole node;
    node.node_id.clear();
    node.no_device = false;
    node.want_train = false;
    std::string err;
    const SwarmEvalRoleResult result = SwarmKeepEvaluator(node, err);
    BOOST_CHECK_EQUAL(result.training, false);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(no_device_is_evaluator)
{
    SwarmEvalRole node;
    node.node_id = "n1";
    node.no_device = true;
    node.want_train = false;
    std::string err;
    const SwarmEvalRoleResult result = SwarmKeepEvaluator(node, err);
    BOOST_CHECK_EQUAL(result.training, false);
    BOOST_CHECK_EQUAL(result.code, "EVALUATOR");
    BOOST_CHECK_EQUAL(err, "EVALUATOR");
}

BOOST_AUTO_TEST_CASE(want_train_is_held)
{
    SwarmEvalRole node;
    node.node_id = "n1";
    node.no_device = false;
    node.want_train = true;
    std::string err;
    const SwarmEvalRoleResult result = SwarmKeepEvaluator(node, err);
    BOOST_CHECK_EQUAL(result.training, false);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(neither_is_noted)
{
    SwarmEvalRole node;
    node.node_id = "n1";
    node.no_device = false;
    node.want_train = false;
    std::string err = "stale";
    const SwarmEvalRoleResult result = SwarmKeepEvaluator(node, err);
    BOOST_CHECK_EQUAL(result.training, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
