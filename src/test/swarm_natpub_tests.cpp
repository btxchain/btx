// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_natpub.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_natpub_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node)
{
    modelnet::SwarmNatPub node;
    node.node_id.clear();
    node.want_publish = false;
    std::string err;
    const modelnet::SwarmNatPubResult result = modelnet::SwarmNoteNatPub(node, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_publish_held)
{
    modelnet::SwarmNatPub node;
    node.node_id = "node-a";
    node.want_publish = true;
    std::string err;
    const modelnet::SwarmNatPubResult result = modelnet::SwarmNoteNatPub(node, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNatPub node;
    node.node_id = "node-b";
    node.want_publish = false;
    std::string err = "stale";
    const modelnet::SwarmNatPubResult result = modelnet::SwarmNoteNatPub(node, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
