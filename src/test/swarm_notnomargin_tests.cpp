// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomargin.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnomargin_tests, BasicTestingSetup)

static modelnet::SwarmNotNoMargin NotedNote()
{
    modelnet::SwarmNotNoMargin note;
    note.channel_id = "channel-1";
    note.blocks = 160;
    note.want_broadcast = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    modelnet::SwarmNotNoMargin note = NotedNote();
    note.channel_id.clear();
    note.blocks = 0;
    note.want_broadcast = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoMarginResult result = modelnet::SwarmNoteNotNoMargin(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.applied_blocks, 0);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(blocks_other_than_160_is_capped)
{
    modelnet::SwarmNotNoMargin note = NotedNote();
    note.blocks = 159;
    note.want_broadcast = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoMarginResult result = modelnet::SwarmNoteNotNoMargin(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.applied_blocks, 0);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(want_broadcast_at_160_is_not_broadcast)
{
    modelnet::SwarmNotNoMargin note = NotedNote();
    note.blocks = 160;
    note.want_broadcast = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoMarginResult result = modelnet::SwarmNoteNotNoMargin(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.applied_blocks, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_BROADCAST");
    BOOST_CHECK_EQUAL(err, "NOT_BROADCAST");
}

BOOST_AUTO_TEST_CASE(plain_160_is_noted)
{
    modelnet::SwarmNotNoMargin note = NotedNote();
    note.blocks = 160;
    note.want_broadcast = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoMarginResult result = modelnet::SwarmNoteNotNoMargin(note, err);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.applied_blocks, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
