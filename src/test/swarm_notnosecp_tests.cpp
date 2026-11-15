// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosecp.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnosecp_tests, BasicTestingSetup)

static modelnet::SwarmNotNoSecp NotedNote()
{
    modelnet::SwarmNotNoSecp note;
    note.channel_id = "channel-1";
    note.want_penalty = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    modelnet::SwarmNotNoSecp note = NotedNote();
    note.channel_id.clear();
    note.want_penalty = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSecpResult result = modelnet::SwarmNoteNotNoSecp(note, err);
    BOOST_CHECK(!result.secp_penalty);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(want_penalty_is_refused)
{
    modelnet::SwarmNotNoSecp note = NotedNote();
    note.want_penalty = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSecpResult result = modelnet::SwarmNoteNotNoSecp(note, err);
    BOOST_CHECK(!result.secp_penalty);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "REFUSED");
    BOOST_CHECK_EQUAL(err, "REFUSED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoSecp note = NotedNote();
    note.want_penalty = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSecpResult result = modelnet::SwarmNoteNotNoSecp(note, err);
    BOOST_CHECK(!result.secp_penalty);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
