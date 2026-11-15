// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnochannel.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnochannel_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    modelnet::SwarmNotNoChannel note;
    note.channel_id.clear();
    note.want_open_second = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoChannelResult result = modelnet::SwarmNoteNotNoChannel(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.channels, 0);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(want_open_second_is_one_channel)
{
    modelnet::SwarmNotNoChannel note;
    note.channel_id = "channel-1";
    note.want_open_second = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoChannelResult result = modelnet::SwarmNoteNotNoChannel(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.channels, 0);
    BOOST_CHECK_EQUAL(result.code, "ONE_CHANNEL");
    BOOST_CHECK_EQUAL(err, "ONE_CHANNEL");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoChannel note;
    note.channel_id = "channel-1";
    note.want_open_second = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoChannelResult result = modelnet::SwarmNoteNotNoChannel(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.channels, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
