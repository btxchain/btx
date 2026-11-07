// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrefundlive.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notrefundlive_tests, BasicTestingSetup)

static modelnet::SwarmNotRefundLive NotedNote()
{
    modelnet::SwarmNotRefundLive note;
    note.channel_id = "channel-1";
    note.want_refund = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    modelnet::SwarmNotRefundLive note = NotedNote();
    note.channel_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotRefundLiveResult result = modelnet::SwarmNoteNotRefundLive(note, err);
    BOOST_CHECK(!result.refunded);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(want_refund_is_not_live)
{
    modelnet::SwarmNotRefundLive note = NotedNote();
    note.want_refund = true;
    std::string err = "prior";
    const modelnet::SwarmNotRefundLiveResult result = modelnet::SwarmNoteNotRefundLive(note, err);
    BOOST_CHECK(!result.refunded);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOT_LIVE");
    BOOST_CHECK_EQUAL(err, "NOT_LIVE");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotRefundLive note = NotedNote();
    note.want_refund = false;
    std::string err = "prior";
    const modelnet::SwarmNotRefundLiveResult result = modelnet::SwarmNoteNotRefundLive(note, err);
    BOOST_CHECK(!result.refunded);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
