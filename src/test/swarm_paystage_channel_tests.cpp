// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paystage/channel.h>
#include <modelnet/swarm_paystage/paystage.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_paystage_channel_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(capacity_and_empty_name_store_nothing)
{
    modelnet::SwarmPayChannel channel;
    std::string err = "prior";
    BOOST_CHECK(channel.open_channel().empty());
    BOOST_CHECK_EQUAL(channel.capacity(), 0);
    BOOST_CHECK_EQUAL(channel.Remaining("channel-1"), -1);

    BOOST_CHECK(!channel.Open("", 10, err));
    BOOST_CHECK_EQUAL(err, "CHANNEL");
    BOOST_CHECK(channel.open_channel().empty());
    BOOST_CHECK_EQUAL(channel.capacity(), 0);
    BOOST_CHECK_EQUAL(channel.Remaining(""), -1);

    err = "prior";
    BOOST_CHECK(!channel.Open("channel-1", 0, err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(channel.Remaining("channel-1"), -1);

    err = "prior";
    BOOST_CHECK(!channel.Open("channel-1", -8, err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK(channel.open_channel().empty());

    err = "prior";
    BOOST_CHECK(!channel.Debit(1, err));
    BOOST_CHECK_EQUAL(err, "CHANNEL");
    BOOST_CHECK_EQUAL(channel.Remaining("channel-1"), -1);
}

BOOST_AUTO_TEST_CASE(second_open_leaves_the_first)
{
    modelnet::SwarmPayChannel channel;
    std::string err = "prior";
    BOOST_REQUIRE(channel.Open("channel-1", 10, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(channel.open_channel(), "channel-1");
    BOOST_CHECK_EQUAL(channel.capacity(), 10);
    BOOST_CHECK_EQUAL(channel.Remaining("channel-1"), 10);

    err = "prior";
    BOOST_CHECK(!channel.Open("channel-2", 99, err));
    BOOST_CHECK_EQUAL(err, "NOT_OPENED");
    BOOST_CHECK_EQUAL(channel.open_channel(), "channel-1");
    BOOST_CHECK_EQUAL(channel.capacity(), 10);
    BOOST_CHECK_EQUAL(channel.Remaining("channel-1"), 10);
    BOOST_CHECK_EQUAL(channel.Remaining("channel-2"), -1);

    err = "prior";
    BOOST_CHECK(!channel.Open("channel-1", 10, err));
    BOOST_CHECK_EQUAL(err, "NOT_OPENED");
    BOOST_CHECK_EQUAL(channel.Remaining("channel-1"), 10);

    err = "prior";
    BOOST_CHECK(!channel.Open("channel-2", 0, err));
    BOOST_CHECK_EQUAL(err, "CAPACITY");
    BOOST_CHECK_EQUAL(channel.open_channel(), "channel-1");
    BOOST_CHECK_EQUAL(channel.capacity(), 10);
    BOOST_CHECK_EQUAL(channel.Remaining("channel-1"), 10);
}

BOOST_AUTO_TEST_CASE(short_debit_and_exact_debit)
{
    modelnet::SwarmPayStage stage;
    std::string err = "prior";
    BOOST_REQUIRE(stage.Open("lane", 5, err));
    BOOST_CHECK_EQUAL(stage.Remaining("missing"), -1);

    err = "prior";
    BOOST_CHECK(!stage.Debit(0, err));
    BOOST_CHECK_EQUAL(err, "ATOMS");
    BOOST_CHECK_EQUAL(stage.Remaining("lane"), 5);

    err = "prior";
    BOOST_CHECK(!stage.Debit(-1, err));
    BOOST_CHECK_EQUAL(err, "ATOMS");
    BOOST_CHECK_EQUAL(stage.Remaining("lane"), 5);

    err = "prior";
    BOOST_CHECK(!stage.Debit(6, err));
    BOOST_CHECK_EQUAL(err, "SHORT");
    BOOST_CHECK_EQUAL(stage.Remaining("lane"), 5);
    BOOST_CHECK_EQUAL(stage.Remaining("other"), -1);

    err = "prior";
    BOOST_REQUIRE(stage.Debit(5, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(stage.Remaining("lane"), 0);
    BOOST_CHECK_EQUAL(stage.capacity(), 5);

    err = "prior";
    BOOST_CHECK(!stage.Debit(1, err));
    BOOST_CHECK_EQUAL(err, "SHORT");
    BOOST_CHECK_EQUAL(stage.Remaining("lane"), 0);
}

BOOST_AUTO_TEST_SUITE_END()
