// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_reorghold/swarm_reorghold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_reorghold_open_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_is_channel_and_stores_nothing)
{
    modelnet::SwarmReorgHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.earned() == 0);
    BOOST_REQUIRE(plane.channels() == 0);
    BOOST_REQUIRE(!plane.frozen());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);

    BOOST_REQUIRE(!plane.Open("", 10, err));
    BOOST_REQUIRE_EQUAL(err, "CHANNEL");
    BOOST_REQUIRE(plane.channels() == 0);
    BOOST_REQUIRE(plane.earned() == 0);
    BOOST_REQUIRE(!plane.has(""));
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_CASE(negative_earned_is_atoms)
{
    modelnet::SwarmReorgHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Open("north", -1, err));
    BOOST_REQUIRE_EQUAL(err, "ATOMS");
    BOOST_REQUIRE(!plane.has("north"));
    BOOST_REQUIRE(plane.earned() == 0);
    BOOST_REQUIRE(plane.channels() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Open("north", std::numeric_limits<int64_t>::min(), err));
    BOOST_REQUIRE_EQUAL(err, "ATOMS");
    BOOST_REQUIRE(plane.earned() == 0);
    BOOST_REQUIRE(!plane.paid("north"));
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_CASE(two_channels_add_earned_once_and_duplicate_is_replay)
{
    modelnet::SwarmReorgHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("north", 40, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.has("north"));
    BOOST_REQUIRE(!plane.channel_frozen("north"));
    BOOST_REQUIRE(plane.channel_earned("north") == 40);
    BOOST_REQUIRE(plane.earned() == 40);
    BOOST_REQUIRE(!plane.frozen());
    BOOST_REQUIRE(!plane.paid("north"));
    BOOST_REQUIRE(!plane.exited("north"));
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);

    BOOST_REQUIRE(plane.Open("south", 60, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.channels() == 2);
    BOOST_REQUIRE(plane.has("south"));
    BOOST_REQUIRE(!plane.channel_frozen("south"));
    BOOST_REQUIRE(plane.channel_earned("south") == 60);
    BOOST_REQUIRE(plane.earned() == 100);

    err = "prior";
    BOOST_REQUIRE(!plane.Open("north", 40, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.channels() == 2);
    BOOST_REQUIRE(plane.earned() == 100);
    BOOST_REQUIRE(plane.channel_earned("north") == 40);

    err = "prior";
    BOOST_REQUIRE(!plane.Open("south", 1, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.earned() == 100);
    BOOST_REQUIRE(!plane.channel_frozen("north"));
    BOOST_REQUIRE(!plane.channel_frozen("south"));
    BOOST_REQUIRE(!plane.refund_built());
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_CASE(zero_earned_is_stored_and_overflow_adds_nothing)
{
    modelnet::SwarmReorgHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("zero", 0, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.has("zero"));
    BOOST_REQUIRE(plane.channel_earned("zero") == 0);
    BOOST_REQUIRE(plane.earned() == 0);

    BOOST_REQUIRE(plane.Open("full", std::numeric_limits<int64_t>::max(), err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.earned() == std::numeric_limits<int64_t>::max());
    BOOST_REQUIRE(plane.channels() == 2);

    err = "prior";
    BOOST_REQUIRE(!plane.Open("overflow", 1, err));
    BOOST_REQUIRE_EQUAL(err, "ATOMS");
    BOOST_REQUIRE(!plane.has("overflow"));
    BOOST_REQUIRE(plane.channels() == 2);
    BOOST_REQUIRE(plane.earned() == std::numeric_limits<int64_t>::max());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
