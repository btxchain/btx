// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_channelone.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_channelone_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(first_open_stores_the_channel)
{
    modelnet::SwarmChannelOne channel;
    BOOST_CHECK(channel.open_channel().empty());
    BOOST_CHECK_EQUAL(channel.capacity(), 0);

    std::string err = "prior";
    BOOST_CHECK(!channel.Open("", 10, err));
    BOOST_CHECK_EQUAL(err, "CHANNEL");
    BOOST_CHECK(channel.open_channel().empty());
    BOOST_CHECK_EQUAL(channel.capacity(), 0);

    err = "prior";
    BOOST_CHECK(!channel.Open("channel-1", 0, err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK(channel.open_channel().empty());
    BOOST_CHECK_EQUAL(channel.capacity(), 0);

    err = "prior";
    BOOST_CHECK(!channel.Open("channel-1", -1, err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK(channel.open_channel().empty());
    BOOST_CHECK_EQUAL(channel.capacity(), 0);

    err = "prior";
    BOOST_REQUIRE(channel.Open("channel-1", 10, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(channel.open_channel(), "channel-1");
    BOOST_CHECK_EQUAL(channel.capacity(), 10);
}

BOOST_AUTO_TEST_CASE(second_open_is_not_opened)
{
    modelnet::SwarmChannelOne channel;
    std::string err = "prior";
    BOOST_REQUIRE(channel.Open("channel-1", 10, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(channel.open_channel(), "channel-1");
    BOOST_CHECK_EQUAL(channel.capacity(), 10);

    err = "prior";
    BOOST_CHECK(!channel.Open("channel-2", 20, err));
    BOOST_CHECK_EQUAL(err, "NOT_OPENED");
    BOOST_CHECK_EQUAL(channel.open_channel(), "channel-1");
    BOOST_CHECK_EQUAL(channel.capacity(), 10);

    err = "prior";
    BOOST_CHECK(!channel.Open("channel-1", 10, err));
    BOOST_CHECK_EQUAL(err, "NOT_OPENED");
    BOOST_CHECK_EQUAL(channel.open_channel(), "channel-1");
    BOOST_CHECK_EQUAL(channel.capacity(), 10);
}

BOOST_AUTO_TEST_SUITE_END()
