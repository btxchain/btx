// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_batterydrain.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_batterydrain_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    std::string err = "prior";
    modelnet::SwarmBatteryDrain node;
    node.battery = true;
    node.want_run = true;
    const modelnet::SwarmBatteryDrainResult result = modelnet::SwarmNoteBatteryDrain(node, err);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(battery_true_want_run_false_is_drained)
{
    std::string err = "prior";
    modelnet::SwarmBatteryDrain node;
    node.node_id = "node-note";
    node.battery = true;
    node.want_run = false;
    const modelnet::SwarmBatteryDrainResult result = modelnet::SwarmNoteBatteryDrain(node, err);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "DRAINED");
    BOOST_CHECK_EQUAL(err, "DRAINED");
}

BOOST_AUTO_TEST_CASE(want_run_true_battery_false_is_held)
{
    std::string err = "prior";
    modelnet::SwarmBatteryDrain node;
    node.node_id = "node-note";
    node.battery = false;
    node.want_run = true;
    const modelnet::SwarmBatteryDrainResult result = modelnet::SwarmNoteBatteryDrain(node, err);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(neither_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmBatteryDrain node;
    node.node_id = "node-note";
    node.battery = false;
    node.want_run = false;
    const modelnet::SwarmBatteryDrainResult result = modelnet::SwarmNoteBatteryDrain(node, err);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
