// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_manifestbind.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_manifestbind_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_root_is_root)
{
    std::string err = "prior";
    modelnet::SwarmManifestBind bind;
    bind.root_id = "";
    bind.children = 2;
    bind.matched = 2;
    bind.want_activate = false;
    const modelnet::SwarmManifestBindResult result = modelnet::SwarmBindChildren(bind, err);
    BOOST_CHECK(!result.activated);
    BOOST_CHECK(!result.bytes_streamed);
    BOOST_CHECK_EQUAL(result.code, "ROOT");
    BOOST_CHECK_EQUAL(err, "ROOT");
}

BOOST_AUTO_TEST_CASE(children_zero_is_empty)
{
    std::string err = "prior";
    modelnet::SwarmManifestBind bind;
    bind.root_id = "root";
    bind.children = 0;
    bind.matched = 0;
    bind.want_activate = false;
    const modelnet::SwarmManifestBindResult result = modelnet::SwarmBindChildren(bind, err);
    BOOST_CHECK(!result.activated);
    BOOST_CHECK(!result.bytes_streamed);
    BOOST_CHECK_EQUAL(result.code, "EMPTY");
    BOOST_CHECK_EQUAL(err, "EMPTY");
}

BOOST_AUTO_TEST_CASE(matched_above_children_is_range)
{
    std::string err = "prior";
    modelnet::SwarmManifestBind bind;
    bind.root_id = "root";
    bind.children = 2;
    bind.matched = 4;
    bind.want_activate = false;
    const modelnet::SwarmManifestBindResult result = modelnet::SwarmBindChildren(bind, err);
    BOOST_CHECK(!result.activated);
    BOOST_CHECK(!result.bytes_streamed);
    BOOST_CHECK_EQUAL(result.code, "RANGE");
    BOOST_CHECK_EQUAL(err, "RANGE");
}

BOOST_AUTO_TEST_CASE(matched_below_children_is_incomplete)
{
    std::string err = "prior";
    modelnet::SwarmManifestBind bind;
    bind.root_id = "root";
    bind.children = 2;
    bind.matched = 1;
    bind.want_activate = false;
    const modelnet::SwarmManifestBindResult result = modelnet::SwarmBindChildren(bind, err);
    BOOST_CHECK(!result.activated);
    BOOST_CHECK(!result.bytes_streamed);
    BOOST_CHECK_EQUAL(result.code, "INCOMPLETE");
    BOOST_CHECK_EQUAL(err, "INCOMPLETE");
}

BOOST_AUTO_TEST_CASE(want_activate_is_held)
{
    std::string err = "prior";
    modelnet::SwarmManifestBind bind;
    bind.root_id = "root";
    bind.children = 2;
    bind.matched = 2;
    bind.want_activate = true;
    const modelnet::SwarmManifestBindResult result = modelnet::SwarmBindChildren(bind, err);
    BOOST_CHECK(!result.activated);
    BOOST_CHECK(!result.bytes_streamed);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(without_want_activate_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmManifestBind bind;
    bind.root_id = "root";
    bind.children = 2;
    bind.matched = 2;
    bind.want_activate = false;
    const modelnet::SwarmManifestBindResult result = modelnet::SwarmBindChildren(bind, err);
    BOOST_CHECK(!result.activated);
    BOOST_CHECK(!result.bytes_streamed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
