// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nobroadcast.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_nobroadcast_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_id_is_broadcast)
{
    std::string err = "prior";
    modelnet::SwarmNoBroadcast note;
    note.want_mainnet = true;
    const modelnet::SwarmNoBroadcastResult result = modelnet::SwarmNoteNoBroadcast(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "BROADCAST");
    BOOST_CHECK_EQUAL(err, "BROADCAST");
}

BOOST_AUTO_TEST_CASE(want_mainnet_is_mainnet)
{
    std::string err = "prior";
    modelnet::SwarmNoBroadcast note;
    note.channel_id = "chan-a";
    note.want_mainnet = true;
    const modelnet::SwarmNoBroadcastResult result = modelnet::SwarmNoteNoBroadcast(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "MAINNET");
    BOOST_CHECK_EQUAL(err, "MAINNET");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNoBroadcast note;
    note.channel_id = "chan-a";
    note.want_mainnet = false;
    const modelnet::SwarmNoBroadcastResult result = modelnet::SwarmNoteNoBroadcast(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
