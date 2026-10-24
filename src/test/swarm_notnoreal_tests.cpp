// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoreal.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoreal_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    std::string err = "prior";
    modelnet::SwarmNotNoReal note;
    note.want_open = true;
    const modelnet::SwarmNotNoRealResult result = modelnet::SwarmNoteNotNoReal(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(want_open_is_real_money)
{
    std::string err = "prior";
    modelnet::SwarmNotNoReal note;
    note.channel_id = "channel-1";
    note.want_open = true;
    const modelnet::SwarmNotNoRealResult result = modelnet::SwarmNoteNotNoReal(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "REAL_MONEY");
    BOOST_CHECK_EQUAL(err, "REAL_MONEY");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoReal note;
    note.channel_id = "channel-1";
    note.want_open = false;
    const modelnet::SwarmNotNoRealResult result = modelnet::SwarmNoteNotNoReal(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
