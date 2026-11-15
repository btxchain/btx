// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmargin.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notmargin_tests, BasicTestingSetup)

static modelnet::SwarmNotMargin NotedNote()
{
    modelnet::SwarmNotMargin note;
    note.channel_id = "channel-1";
    note.blocks = 160;
    note.want_close = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    modelnet::SwarmNotMargin note = NotedNote();
    note.channel_id.clear();
    note.blocks = 159;
    note.want_close = true;
    std::string err = "prior";
    const modelnet::SwarmNotMarginResult result = modelnet::SwarmNoteNotMargin(note, err);
    BOOST_CHECK(!result.closed);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(blocks_159_is_held)
{
    modelnet::SwarmNotMargin note = NotedNote();
    note.blocks = 159;
    note.want_close = false;
    std::string err = "prior";
    const modelnet::SwarmNotMarginResult result = modelnet::SwarmNoteNotMargin(note, err);
    BOOST_CHECK(!result.closed);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_close_with_blocks_160_is_held)
{
    modelnet::SwarmNotMargin note = NotedNote();
    note.blocks = 160;
    note.want_close = true;
    std::string err = "prior";
    const modelnet::SwarmNotMarginResult result = modelnet::SwarmNoteNotMargin(note, err);
    BOOST_CHECK(!result.closed);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_with_blocks_160_is_noted)
{
    modelnet::SwarmNotMargin note = NotedNote();
    note.blocks = 160;
    note.want_close = false;
    std::string err = "prior";
    const modelnet::SwarmNotMarginResult result = modelnet::SwarmNoteNotMargin(note, err);
    BOOST_CHECK(!result.closed);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
