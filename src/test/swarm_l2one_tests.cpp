// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_l2one.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_l2one_tests, BasicTestingSetup)

static modelnet::SwarmL2One NotedChannel()
{
    modelnet::SwarmL2One channel;
    channel.channel_id = "channel-1";
    channel.second_channel = false;
    channel.want_open = false;
    return channel;
}

BOOST_AUTO_TEST_CASE(empty_channel_is_channel)
{
    modelnet::SwarmL2One channel = NotedChannel();
    channel.channel_id.clear();
    std::string err = "prior";
    const modelnet::SwarmL2OneResult result = modelnet::SwarmKeepOneChannel(channel, err);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(second_channel_is_not_opened)
{
    modelnet::SwarmL2One channel = NotedChannel();
    channel.second_channel = true;
    channel.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmL2OneResult result = modelnet::SwarmKeepOneChannel(channel, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_OPENED");
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(err, "NOT_OPENED");
}

BOOST_AUTO_TEST_CASE(want_open_is_held)
{
    modelnet::SwarmL2One channel = NotedChannel();
    channel.want_open = true;
    channel.second_channel = false;
    std::string err = "prior";
    const modelnet::SwarmL2OneResult result = modelnet::SwarmKeepOneChannel(channel, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmL2One channel = NotedChannel();
    channel.second_channel = false;
    channel.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmL2OneResult result = modelnet::SwarmKeepOneChannel(channel, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
