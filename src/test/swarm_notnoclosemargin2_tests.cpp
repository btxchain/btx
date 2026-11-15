// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoclosemargin2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoclosemargin2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoCloseMargin2 NotedNote()
{
    modelnet::SwarmNotNoCloseMargin2 note;
    note.channel_id = "channel-1";
    note.want_shrink = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    modelnet::SwarmNotNoCloseMargin2 note = NotedNote();
    note.channel_id.clear();
    note.want_shrink = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCloseMargin2Result result = modelnet::SwarmNoteNotNoCloseMargin2(note, err);
    BOOST_CHECK(!result.shrunk);
    BOOST_CHECK_EQUAL(result.blocks, 160);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(want_shrink_is_held)
{
    modelnet::SwarmNotNoCloseMargin2 note = NotedNote();
    note.want_shrink = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCloseMargin2Result result = modelnet::SwarmNoteNotNoCloseMargin2(note, err);
    BOOST_CHECK(!result.shrunk);
    BOOST_CHECK_EQUAL(result.blocks, 160);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoCloseMargin2 note = NotedNote();
    note.want_shrink = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCloseMargin2Result result = modelnet::SwarmNoteNotNoCloseMargin2(note, err);
    BOOST_CHECK(!result.shrunk);
    BOOST_CHECK_EQUAL(result.blocks, 160);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
