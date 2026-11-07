// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_not14400.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_not14400_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    std::string err = "prior";
    modelnet::SwarmNot14400 note;
    note.blocks = 160;
    note.want_guarantee = true;
    const modelnet::SwarmNot14400Result result = modelnet::SwarmNoteNot14400(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(blocks_159_is_not_guarantee)
{
    std::string err = "prior";
    modelnet::SwarmNot14400 note;
    note.channel_id = "channel-note";
    note.blocks = 159;
    note.want_guarantee = false;
    const modelnet::SwarmNot14400Result result = modelnet::SwarmNoteNot14400(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_GUARANTEE");
    BOOST_CHECK_EQUAL(err, "NOT_GUARANTEE");
}

BOOST_AUTO_TEST_CASE(blocks_161_is_not_guarantee)
{
    std::string err = "prior";
    modelnet::SwarmNot14400 note;
    note.channel_id = "channel-note";
    note.blocks = 161;
    note.want_guarantee = false;
    const modelnet::SwarmNot14400Result result = modelnet::SwarmNoteNot14400(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_GUARANTEE");
    BOOST_CHECK_EQUAL(err, "NOT_GUARANTEE");
}

BOOST_AUTO_TEST_CASE(blocks_160_with_want_guarantee_is_not_guarantee)
{
    std::string err = "prior";
    modelnet::SwarmNot14400 note;
    note.channel_id = "channel-note";
    note.blocks = 160;
    note.want_guarantee = true;
    const modelnet::SwarmNot14400Result result = modelnet::SwarmNoteNot14400(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_GUARANTEE");
    BOOST_CHECK_EQUAL(err, "NOT_GUARANTEE");
}

BOOST_AUTO_TEST_CASE(blocks_160_plain_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNot14400 note;
    note.channel_id = "channel-note";
    note.blocks = 160;
    note.want_guarantee = false;
    const modelnet::SwarmNot14400Result result = modelnet::SwarmNoteNot14400(note, err);
    BOOST_CHECK(!result.guaranteed);
    BOOST_CHECK_EQUAL(result.seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
