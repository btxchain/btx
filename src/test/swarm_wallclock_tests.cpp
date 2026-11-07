// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_wallclock.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_wallclock_tests, BasicTestingSetup)

static modelnet::SwarmWallClock NotedClock()
{
    modelnet::SwarmWallClock clock;
    clock.channel_id = "channel-a";
    clock.blocks = 160;
    clock.want_guarantee = false;
    return clock;
}

BOOST_AUTO_TEST_CASE(empty_channel_id_is_elapsed)
{
    modelnet::SwarmWallClock clock = NotedClock();
    clock.channel_id.clear();
    clock.want_guarantee = true;
    std::string err = "prior";
    const modelnet::SwarmWallClockResult result = modelnet::SwarmNoteWallClock(clock, err);
    BOOST_CHECK(!result.wall_clock_guaranteed);
    BOOST_CHECK_EQUAL(result.elapsed_seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "ELAPSED");
    BOOST_CHECK_EQUAL(err, "ELAPSED");
}

BOOST_AUTO_TEST_CASE(negative_blocks_are_elapsed)
{
    modelnet::SwarmWallClock clock = NotedClock();
    clock.blocks = -1;
    clock.want_guarantee = true;
    std::string err = "prior";
    const modelnet::SwarmWallClockResult result = modelnet::SwarmNoteWallClock(clock, err);
    BOOST_CHECK(!result.wall_clock_guaranteed);
    BOOST_CHECK_EQUAL(result.elapsed_seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "ELAPSED");
    BOOST_CHECK_EQUAL(err, "ELAPSED");
}

BOOST_AUTO_TEST_CASE(want_guarantee_at_160_is_not_guaranteed)
{
    modelnet::SwarmWallClock clock = NotedClock();
    clock.blocks = 160;
    clock.want_guarantee = true;
    std::string err = "prior";
    const modelnet::SwarmWallClockResult result = modelnet::SwarmNoteWallClock(clock, err);
    BOOST_CHECK(!result.wall_clock_guaranteed);
    BOOST_CHECK_EQUAL(result.elapsed_seconds, 14400);
    BOOST_CHECK_EQUAL(result.code, "NOT_GUARANTEED");
    BOOST_CHECK_EQUAL(err, "NOT_GUARANTEED");
}

BOOST_AUTO_TEST_CASE(one_hundred_sixty_blocks_are_noted)
{
    modelnet::SwarmWallClock clock = NotedClock();
    clock.blocks = 160;
    clock.want_guarantee = false;
    std::string err = "prior";
    const modelnet::SwarmWallClockResult result = modelnet::SwarmNoteWallClock(clock, err);
    BOOST_CHECK(!result.wall_clock_guaranteed);
    BOOST_CHECK_EQUAL(result.elapsed_seconds, 14400);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(six_thousand_seven_hundred_twenty_blocks_are_noted)
{
    modelnet::SwarmWallClock clock = NotedClock();
    clock.blocks = 6720;
    clock.want_guarantee = false;
    std::string err = "prior";
    const modelnet::SwarmWallClockResult result = modelnet::SwarmNoteWallClock(clock, err);
    BOOST_CHECK(!result.wall_clock_guaranteed);
    BOOST_CHECK_EQUAL(result.elapsed_seconds, 604800);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(overflow_blocks_are_elapsed)
{
    modelnet::SwarmWallClock clock = NotedClock();
    clock.blocks = INT64_MAX;
    clock.want_guarantee = true;
    std::string err = "prior";
    const modelnet::SwarmWallClockResult result = modelnet::SwarmNoteWallClock(clock, err);
    BOOST_CHECK(!result.wall_clock_guaranteed);
    BOOST_CHECK_EQUAL(result.elapsed_seconds, 0);
    BOOST_CHECK_EQUAL(result.code, "ELAPSED");
    BOOST_CHECK_EQUAL(err, "ELAPSED");
}

BOOST_AUTO_TEST_SUITE_END()
