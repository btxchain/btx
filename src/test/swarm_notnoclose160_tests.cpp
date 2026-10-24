// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoclose160.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoclose160_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    std::string err = "prior";
    modelnet::SwarmNotNoClose160 note;
    note.want_close = true;
    const modelnet::SwarmNotNoClose160Result result = modelnet::SwarmNoteNotNoClose160(note, err);
    BOOST_CHECK(!result.closed);
    BOOST_CHECK_EQUAL(result.height, 0);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(want_close_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoClose160 note;
    note.channel_id = "channel-note";
    note.want_close = true;
    const modelnet::SwarmNotNoClose160Result result = modelnet::SwarmNoteNotNoClose160(note, err);
    BOOST_CHECK(!result.closed);
    BOOST_CHECK_EQUAL(result.height, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoClose160 note;
    note.channel_id = "channel-note";
    note.want_close = false;
    const modelnet::SwarmNotNoClose160Result result = modelnet::SwarmNoteNotNoClose160(note, err);
    BOOST_CHECK(!result.closed);
    BOOST_CHECK_EQUAL(result.height, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
