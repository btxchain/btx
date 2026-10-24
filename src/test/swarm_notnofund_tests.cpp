// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofund.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnofund_tests, BasicTestingSetup)

static modelnet::SwarmNotNoFund NotedNote()
{
    modelnet::SwarmNotNoFund note;
    note.channel_id = "channel-1";
    note.want_broadcast = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    modelnet::SwarmNotNoFund note = NotedNote();
    note.channel_id.clear();
    note.want_broadcast = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFundResult result = modelnet::SwarmNoteNotNoFund(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.confirmed);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(want_broadcast_is_not_open)
{
    modelnet::SwarmNotNoFund note = NotedNote();
    note.want_broadcast = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFundResult result = modelnet::SwarmNoteNotNoFund(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.confirmed);
    BOOST_CHECK_EQUAL(result.code, "NOT_OPEN");
    BOOST_CHECK_EQUAL(err, "NOT_OPEN");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoFund note = NotedNote();
    note.want_broadcast = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFundResult result = modelnet::SwarmNoteNotNoFund(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.confirmed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
