// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmodelon.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notmodelon_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmNotModelOn note;
    note.modelnet_on = false;
    note.want_disable = true;
    std::string err = "prior";
    const modelnet::SwarmNotModelOnResult result = modelnet::SwarmNoteNotModelOn(note, err);
    BOOST_CHECK(!result.disabled);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(modelnet_on_false_is_default_on)
{
    modelnet::SwarmNotModelOn note;
    note.node_id = "node-1";
    note.modelnet_on = false;
    note.want_disable = false;
    std::string err = "prior";
    const modelnet::SwarmNotModelOnResult result = modelnet::SwarmNoteNotModelOn(note, err);
    BOOST_CHECK(!result.disabled);
    BOOST_CHECK_EQUAL(result.code, "DEFAULT_ON");
    BOOST_CHECK_EQUAL(err, "DEFAULT_ON");
}

BOOST_AUTO_TEST_CASE(want_disable_is_default_on)
{
    modelnet::SwarmNotModelOn note;
    note.node_id = "node-1";
    note.modelnet_on = true;
    note.want_disable = true;
    std::string err = "prior";
    const modelnet::SwarmNotModelOnResult result = modelnet::SwarmNoteNotModelOn(note, err);
    BOOST_CHECK(!result.disabled);
    BOOST_CHECK_EQUAL(result.code, "DEFAULT_ON");
    BOOST_CHECK_EQUAL(err, "DEFAULT_ON");
}

BOOST_AUTO_TEST_CASE(plain_on_is_noted)
{
    modelnet::SwarmNotModelOn note;
    BOOST_CHECK(note.modelnet_on);
    BOOST_CHECK(!note.want_disable);
    note.node_id = "node-1";
    std::string err = "prior";
    const modelnet::SwarmNotModelOnResult result = modelnet::SwarmNoteNotModelOn(note, err);
    BOOST_CHECK(!result.disabled);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
