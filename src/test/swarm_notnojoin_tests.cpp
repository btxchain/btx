// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnojoin.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnojoin_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty)
{
    std::string err = "prior";
    modelnet::SwarmNotNoJoin note;
    note.node_id.clear();
    note.modelnet_on = true;
    note.want_skip = true;
    const modelnet::SwarmNotNoJoinResult result = modelnet::SwarmNoteNotNoJoin(note, err);
    BOOST_CHECK(!result.skipped);
    BOOST_CHECK(!result.joined);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(modelnet_on)
{
    std::string err = "prior";
    modelnet::SwarmNotNoJoin note;
    note.node_id = "node-1";
    note.modelnet_on = true;
    note.want_skip = false;
    const modelnet::SwarmNotNoJoinResult result = modelnet::SwarmNoteNotNoJoin(note, err);
    BOOST_CHECK(!result.skipped);
    BOOST_CHECK(!result.joined);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_skip_while_modelnet_is_off)
{
    std::string err = "prior";
    modelnet::SwarmNotNoJoin note;
    note.node_id = "node-1";
    note.modelnet_on = false;
    note.want_skip = true;
    const modelnet::SwarmNotNoJoinResult result = modelnet::SwarmNoteNotNoJoin(note, err);
    BOOST_CHECK(!result.skipped);
    BOOST_CHECK(!result.joined);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_modelnet_off)
{
    std::string err = "prior";
    modelnet::SwarmNotNoJoin note;
    note.node_id = "node-1";
    note.modelnet_on = false;
    note.want_skip = false;
    const modelnet::SwarmNotNoJoinResult result = modelnet::SwarmNoteNotNoJoin(note, err);
    BOOST_CHECK(!result.skipped);
    BOOST_CHECK(!result.joined);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
