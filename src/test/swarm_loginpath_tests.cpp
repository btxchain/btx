// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_loginpath.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_loginpath_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_is_node)
{
    modelnet::SwarmLoginPath node;
    node.node_id.clear();
    node.want_login = true;
    std::string err = "prior";
    const modelnet::SwarmLoginPathResult result = modelnet::SwarmNoteLoginPath(node, err);
    BOOST_CHECK(!result.logged_in);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_login_is_held)
{
    modelnet::SwarmLoginPath node;
    node.node_id = "node-1";
    node.want_login = true;
    std::string err = "prior";
    const modelnet::SwarmLoginPathResult result = modelnet::SwarmNoteLoginPath(node, err);
    BOOST_CHECK(!result.logged_in);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_login_false_is_noted)
{
    modelnet::SwarmLoginPath node;
    node.node_id = "node-1";
    node.want_login = false;
    std::string err = "prior";
    const modelnet::SwarmLoginPathResult result = modelnet::SwarmNoteLoginPath(node, err);
    BOOST_CHECK(!result.logged_in);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
