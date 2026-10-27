// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_seedrole.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_seedrole_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_is_node)
{
    std::string err = "prior";
    modelnet::SwarmSeedRole node;
    node.node_id.clear();
    node.no_device = false;
    node.want_train = false;
    const modelnet::SwarmSeedRoleResult result = modelnet::SwarmKeepSeeder(node, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(no_device_is_seeder)
{
    std::string err = "prior";
    modelnet::SwarmSeedRole node;
    node.node_id = "node";
    node.no_device = true;
    node.want_train = false;
    const modelnet::SwarmSeedRoleResult result = modelnet::SwarmKeepSeeder(node, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "SEEDER");
    BOOST_CHECK_EQUAL(err, "SEEDER");
}

BOOST_AUTO_TEST_CASE(want_train_is_held)
{
    std::string err = "prior";
    modelnet::SwarmSeedRole node;
    node.node_id = "node";
    node.no_device = false;
    node.want_train = true;
    const modelnet::SwarmSeedRoleResult result = modelnet::SwarmKeepSeeder(node, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_node_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmSeedRole node;
    node.node_id = "node";
    node.no_device = false;
    node.want_train = false;
    const modelnet::SwarmSeedRoleResult result = modelnet::SwarmKeepSeeder(node, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
