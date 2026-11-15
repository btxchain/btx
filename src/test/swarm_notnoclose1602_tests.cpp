// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoclose1602.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoclose1602_tests, BasicTestingSetup)

static modelnet::SwarmNotNoClose1602 NotedNote()
{
    modelnet::SwarmNotNoClose1602 note;
    note.channel_id = "channel-1";
    note.margin_blocks = 160;
    note.want_close = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    modelnet::SwarmNotNoClose1602 note = NotedNote();
    note.channel_id.clear();
    note.margin_blocks = 0;
    note.want_close = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoClose1602Result result = modelnet::SwarmNoteNotNoClose1602(note, err);
    BOOST_CHECK(!result.closed);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(margin_blocks_other_than_160_is_capped)
{
    modelnet::SwarmNotNoClose1602 note = NotedNote();
    note.margin_blocks = 159;
    note.want_close = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoClose1602Result result = modelnet::SwarmNoteNotNoClose1602(note, err);
    BOOST_CHECK(!result.closed);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(want_close_at_160_is_capped)
{
    modelnet::SwarmNotNoClose1602 note = NotedNote();
    note.margin_blocks = 160;
    note.want_close = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoClose1602Result result = modelnet::SwarmNoteNotNoClose1602(note, err);
    BOOST_CHECK(!result.closed);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(plain_160_is_noted)
{
    modelnet::SwarmNotNoClose1602 note = NotedNote();
    note.margin_blocks = 160;
    note.want_close = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoClose1602Result result = modelnet::SwarmNoteNotNoClose1602(note, err);
    BOOST_CHECK(!result.closed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
