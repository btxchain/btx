// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnol2channel2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnol2channel2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    modelnet::SwarmNotNoL2Channel2 note;
    note.channel_id.clear();
    note.second_channel = true;
    note.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoL2Channel2Result result = modelnet::SwarmNoteNotNoL2Channel2(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(second_channel_is_not_opened)
{
    modelnet::SwarmNotNoL2Channel2 note;
    note.channel_id = "channel-1";
    note.second_channel = true;
    note.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoL2Channel2Result result = modelnet::SwarmNoteNotNoL2Channel2(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.code, "NOT_OPENED");
    BOOST_CHECK_EQUAL(err, "NOT_OPENED");
}

BOOST_AUTO_TEST_CASE(want_open_is_held)
{
    modelnet::SwarmNotNoL2Channel2 note;
    note.channel_id = "channel-1";
    note.second_channel = false;
    note.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoL2Channel2Result result = modelnet::SwarmNoteNotNoL2Channel2(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoL2Channel2 note;
    note.channel_id = "channel-1";
    note.second_channel = false;
    note.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoL2Channel2Result result = modelnet::SwarmNoteNotNoL2Channel2(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
