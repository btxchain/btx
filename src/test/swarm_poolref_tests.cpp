// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_poolref.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_poolref_tests, BasicTestingSetup)

static modelnet::SwarmPoolChannel NotedChannel()
{
    modelnet::SwarmPoolChannel channel;
    channel.outpoint = "outpoint-a";
    channel.pool_id = "pool-a";
    channel.already_owned = false;
    channel.want_open = false;
    channel.want_reference = false;
    return channel;
}

BOOST_AUTO_TEST_CASE(empty_outpoint_is_channel)
{
    modelnet::SwarmPoolChannel channel = NotedChannel();
    channel.outpoint.clear();
    channel.already_owned = true;
    channel.want_open = true;
    channel.want_reference = true;
    std::string err = "prior";
    const modelnet::SwarmPoolChannelResult result = modelnet::SwarmNotePoolChannel(channel, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(empty_pool_id_is_channel)
{
    modelnet::SwarmPoolChannel channel = NotedChannel();
    channel.pool_id.clear();
    channel.already_owned = true;
    channel.want_open = true;
    channel.want_reference = true;
    std::string err = "prior";
    const modelnet::SwarmPoolChannelResult result = modelnet::SwarmNotePoolChannel(channel, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(collateral_reuse_wins_over_want_reference)
{
    modelnet::SwarmPoolChannel channel = NotedChannel();
    channel.already_owned = true;
    channel.want_open = true;
    channel.want_reference = true;
    std::string err = "prior";
    const modelnet::SwarmPoolChannelResult result = modelnet::SwarmNotePoolChannel(channel, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.code, "COLLATERAL_REUSE");
    BOOST_CHECK_EQUAL(err, "COLLATERAL_REUSE");
}

BOOST_AUTO_TEST_CASE(want_open_on_owned_outpoint_without_reference_is_collateral_reuse)
{
    modelnet::SwarmPoolChannel channel = NotedChannel();
    channel.already_owned = true;
    channel.want_open = true;
    channel.want_reference = false;
    std::string err = "prior";
    const modelnet::SwarmPoolChannelResult result = modelnet::SwarmNotePoolChannel(channel, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.code, "COLLATERAL_REUSE");
    BOOST_CHECK_EQUAL(err, "COLLATERAL_REUSE");
}

BOOST_AUTO_TEST_CASE(want_open_is_held_and_does_not_open)
{
    modelnet::SwarmPoolChannel channel = NotedChannel();
    channel.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmPoolChannelResult result = modelnet::SwarmNotePoolChannel(channel, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(want_open_wins_over_want_reference)
{
    modelnet::SwarmPoolChannel channel = NotedChannel();
    channel.already_owned = false;
    channel.want_open = true;
    channel.want_reference = true;
    std::string err = "prior";
    const modelnet::SwarmPoolChannelResult result = modelnet::SwarmNotePoolChannel(channel, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(reference_without_ownership_is_no_channel)
{
    modelnet::SwarmPoolChannel channel = NotedChannel();
    channel.already_owned = false;
    channel.want_reference = true;
    std::string err = "prior";
    const modelnet::SwarmPoolChannelResult result = modelnet::SwarmNotePoolChannel(channel, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.code, "NO_CHANNEL");
    BOOST_CHECK_EQUAL(err, "NO_CHANNEL");
}

BOOST_AUTO_TEST_CASE(reference_of_owned_channel_is_noted)
{
    modelnet::SwarmPoolChannel channel = NotedChannel();
    channel.already_owned = true;
    channel.want_open = false;
    channel.want_reference = true;
    std::string err = "prior";
    const modelnet::SwarmPoolChannelResult result = modelnet::SwarmNotePoolChannel(channel, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmPoolChannel channel = NotedChannel();
    std::string err = "prior";
    const modelnet::SwarmPoolChannelResult result = modelnet::SwarmNotePoolChannel(channel, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
