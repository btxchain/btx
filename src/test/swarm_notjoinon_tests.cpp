// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notjoinon.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notjoinon_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmNotJoinOn note;
    std::string err = "prior";
    const modelnet::SwarmNotJoinOnResult result = modelnet::SwarmNoteNotJoinOn(note, err);
    BOOST_CHECK_EQUAL(result.skipped, false);
    BOOST_CHECK_EQUAL(result.joined, false);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(modelnet_off_is_default_on)
{
    modelnet::SwarmNotJoinOn note;
    note.node_id = "node-1";
    note.modelnet_on = false;
    note.want_skip_join = false;
    std::string err = "prior";
    const modelnet::SwarmNotJoinOnResult result = modelnet::SwarmNoteNotJoinOn(note, err);
    BOOST_CHECK_EQUAL(result.skipped, false);
    BOOST_CHECK_EQUAL(result.joined, false);
    BOOST_CHECK_EQUAL(result.code, "DEFAULT_ON");
    BOOST_CHECK_EQUAL(err, "DEFAULT_ON");
}

BOOST_AUTO_TEST_CASE(want_skip_join_is_held)
{
    modelnet::SwarmNotJoinOn note;
    note.node_id = "node-1";
    note.modelnet_on = true;
    note.want_skip_join = true;
    std::string err = "prior";
    const modelnet::SwarmNotJoinOnResult result = modelnet::SwarmNoteNotJoinOn(note, err);
    BOOST_CHECK_EQUAL(result.skipped, false);
    BOOST_CHECK_EQUAL(result.joined, false);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_on_is_noted)
{
    modelnet::SwarmNotJoinOn note;
    note.node_id = "node-1";
    note.modelnet_on = true;
    note.want_skip_join = false;
    std::string err = "prior";
    const modelnet::SwarmNotJoinOnResult result = modelnet::SwarmNoteNotJoinOn(note, err);
    BOOST_CHECK_EQUAL(result.skipped, false);
    BOOST_CHECK_EQUAL(result.joined, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
