// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_reorg.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_reorg_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(no_broadcast_is_reorg_no_broadcast)
{
    modelnet::SwarmReorgChannel channel;
    channel.broadcast = false;
    channel.confirmations = 6;
    channel.in_flight_released = true;
    channel.confirmed = true;
    modelnet::SwarmReorgResult result;
    result.code = "prior";
    BOOST_CHECK(!modelnet::SwarmNoteReorg(channel, 2, result));
    BOOST_CHECK_EQUAL(result.code, "REORG_NO_BROADCAST");
    BOOST_CHECK(!channel.broadcast);
    BOOST_CHECK_EQUAL(channel.confirmations, 0);
    BOOST_CHECK(!channel.in_flight_released);
    BOOST_CHECK(!channel.confirmed);

    channel.confirmations = 6;
    channel.in_flight_released = true;
    channel.confirmed = true;
    result.code = "prior";
    BOOST_CHECK(!modelnet::SwarmNoteReorg(channel, -1, result));
    BOOST_CHECK_EQUAL(result.code, "REORG_NO_BROADCAST");
    BOOST_CHECK_EQUAL(channel.confirmations, 0);
    BOOST_CHECK(!channel.in_flight_released);
    BOOST_CHECK(!channel.confirmed);
}

BOOST_AUTO_TEST_CASE(negative_count_is_reorg)
{
    modelnet::SwarmReorgChannel channel;
    channel.broadcast = true;
    channel.confirmations = 6;
    channel.in_flight_released = true;
    channel.confirmed = true;
    modelnet::SwarmReorgResult result;
    result.code = "prior";
    BOOST_CHECK(!modelnet::SwarmNoteReorg(channel, -1, result));
    BOOST_CHECK_EQUAL(result.code, "REORG");
    BOOST_CHECK(channel.broadcast);
    BOOST_CHECK_EQUAL(channel.confirmations, 6);
    BOOST_CHECK(!channel.in_flight_released);
    BOOST_CHECK(!channel.confirmed);
}

BOOST_AUTO_TEST_CASE(drop_from_six_to_two_is_held)
{
    modelnet::SwarmReorgChannel channel;
    channel.broadcast = true;
    channel.confirmations = 6;
    channel.in_flight_released = true;
    channel.confirmed = true;
    modelnet::SwarmReorgResult result;
    result.code = "prior";
    BOOST_CHECK(modelnet::SwarmNoteReorg(channel, 2, result));
    BOOST_CHECK_EQUAL(result.code, "REORG_HELD");
    BOOST_CHECK(channel.broadcast);
    BOOST_CHECK_EQUAL(channel.confirmations, 2);
    BOOST_CHECK(!channel.in_flight_released);
    BOOST_CHECK(!channel.confirmed);

    channel.in_flight_released = true;
    channel.confirmed = true;
    result.code = "prior";
    BOOST_CHECK(modelnet::SwarmNoteReorg(channel, 9, result));
    BOOST_CHECK_EQUAL(result.code, "REORG_HELD");
    BOOST_CHECK_EQUAL(channel.confirmations, 2);
    BOOST_CHECK(!channel.in_flight_released);
    BOOST_CHECK(!channel.confirmed);
}

BOOST_AUTO_TEST_SUITE_END()
