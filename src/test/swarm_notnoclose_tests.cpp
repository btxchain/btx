// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoclose.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoclose_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    std::string err = "prior";
    modelnet::SwarmNotNoClose note;
    note.want_broadcast = true;
    const modelnet::SwarmNotNoCloseResult result = modelnet::SwarmNoteNotNoClose(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.assumed_bytes, 0);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(want_broadcast_is_not_broadcast)
{
    std::string err = "prior";
    modelnet::SwarmNotNoClose note;
    note.channel_id = "channel-1";
    note.want_broadcast = true;
    const modelnet::SwarmNotNoCloseResult result = modelnet::SwarmNoteNotNoClose(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.assumed_bytes, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_BROADCAST");
    BOOST_CHECK_EQUAL(err, "NOT_BROADCAST");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoClose note;
    note.channel_id = "channel-1";
    note.want_broadcast = false;
    const modelnet::SwarmNotNoCloseResult result = modelnet::SwarmNoteNotNoClose(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.assumed_bytes, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
