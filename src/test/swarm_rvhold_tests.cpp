// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rvhold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_rvhold_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmRvHold node;
    node.node_id.clear();
    node.public_rv = true;
    node.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmRvHoldResult result = modelnet::SwarmHoldRendezvous(node, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(public_rv_is_held_when_want_open_is_false)
{
    modelnet::SwarmRvHold node;
    node.node_id = "node-1";
    node.public_rv = true;
    node.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmRvHoldResult result = modelnet::SwarmHoldRendezvous(node, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_open_is_held_when_public_rv_is_false)
{
    modelnet::SwarmRvHold node;
    node.node_id = "node-1";
    node.public_rv = false;
    node.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmRvHoldResult result = modelnet::SwarmHoldRendezvous(node, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_record_is_noted)
{
    modelnet::SwarmRvHold node;
    node.node_id = "node-1";
    node.public_rv = false;
    node.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmRvHoldResult result = modelnet::SwarmHoldRendezvous(node, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
