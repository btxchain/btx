// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmainnet.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notmainnet_tests, BasicTestingSetup)

static modelnet::SwarmNotMainnet NotedNote()
{
    modelnet::SwarmNotMainnet note;
    note.request_id = "request-1";
    note.want_mainnet = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_request_id_is_request)
{
    modelnet::SwarmNotMainnet note = NotedNote();
    note.request_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotMainnetResult result = modelnet::SwarmNoteNotMainnet(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.mined);
    BOOST_CHECK_EQUAL(result.code, "REQUEST");
    BOOST_CHECK_EQUAL(err, "REQUEST");
}

BOOST_AUTO_TEST_CASE(want_mainnet_is_mainnet)
{
    modelnet::SwarmNotMainnet note = NotedNote();
    note.want_mainnet = true;
    std::string err = "prior";
    const modelnet::SwarmNotMainnetResult result = modelnet::SwarmNoteNotMainnet(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.mined);
    BOOST_CHECK_EQUAL(result.code, "MAINNET");
    BOOST_CHECK_EQUAL(err, "MAINNET");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotMainnet note = NotedNote();
    note.want_mainnet = false;
    std::string err = "prior";
    const modelnet::SwarmNotMainnetResult result = modelnet::SwarmNoteNotMainnet(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.mined);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
