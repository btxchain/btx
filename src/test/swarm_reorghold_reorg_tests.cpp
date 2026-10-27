// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_reorghold/swarm_reorghold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_reorghold_reorg_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(reorg_freezes_both_channels_and_keeps_earned)
{
    modelnet::SwarmReorgHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("north", 40, err));
    BOOST_REQUIRE(plane.Open("south", 25, err));
    BOOST_REQUIRE(plane.earned() == 65);
    BOOST_REQUIRE(!plane.frozen());
    BOOST_REQUIRE(!plane.channel_frozen("north"));
    BOOST_REQUIRE(!plane.channel_frozen("south"));

    BOOST_REQUIRE(plane.Reorg(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.frozen());
    BOOST_REQUIRE(plane.channels() == 2);
    BOOST_REQUIRE(plane.has("north"));
    BOOST_REQUIRE(plane.has("south"));
    BOOST_REQUIRE(plane.channel_frozen("north"));
    BOOST_REQUIRE(plane.channel_frozen("south"));
    BOOST_REQUIRE(plane.channel_earned("north") == 40);
    BOOST_REQUIRE(plane.channel_earned("south") == 25);
    BOOST_REQUIRE(plane.earned() == 65);
    BOOST_REQUIRE(!plane.paid("north"));
    BOOST_REQUIRE(!plane.paid("south"));
    BOOST_REQUIRE(!plane.exited("north"));
    BOOST_REQUIRE(!plane.exited("south"));
    BOOST_REQUIRE(!plane.refund_built());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_CASE(second_reorg_is_replay_and_stays_frozen)
{
    modelnet::SwarmReorgHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("north", 10, err));
    BOOST_REQUIRE(plane.Open("south", 15, err));
    BOOST_REQUIRE(plane.Reorg(err));
    BOOST_REQUIRE(plane.earned() == 25);

    err = "prior";
    BOOST_REQUIRE(!plane.Reorg(err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.frozen());
    BOOST_REQUIRE(plane.channel_frozen("north"));
    BOOST_REQUIRE(plane.channel_frozen("south"));
    BOOST_REQUIRE(plane.earned() == 25);
    BOOST_REQUIRE(plane.channels() == 2);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.refund_built());
}

BOOST_AUTO_TEST_CASE(open_while_frozen_is_frozen_and_adds_nothing)
{
    modelnet::SwarmReorgHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("north", 40, err));
    BOOST_REQUIRE(plane.Open("south", 60, err));
    BOOST_REQUIRE(plane.Reorg(err));
    BOOST_REQUIRE(plane.earned() == 100);

    err = "prior";
    BOOST_REQUIRE(!plane.Open("east", 5, err));
    BOOST_REQUIRE_EQUAL(err, "FROZEN");
    BOOST_REQUIRE(!plane.has("east"));
    BOOST_REQUIRE(plane.channels() == 2);
    BOOST_REQUIRE(plane.earned() == 100);
    BOOST_REQUIRE(plane.channel_earned("north") == 40);
    BOOST_REQUIRE(plane.channel_earned("south") == 60);

    err = "prior";
    BOOST_REQUIRE(!plane.Open("north", 40, err));
    BOOST_REQUIRE_EQUAL(err, "FROZEN");
    BOOST_REQUIRE(plane.earned() == 100);
    BOOST_REQUIRE(plane.channel_earned("north") == 40);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_CASE(reorg_with_no_channel_still_freezes_later_open)
{
    modelnet::SwarmReorgHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Reorg(err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.frozen());
    BOOST_REQUIRE(plane.earned() == 0);
    BOOST_REQUIRE(plane.channels() == 0);
    BOOST_REQUIRE(!plane.broadcast());

    BOOST_REQUIRE(!plane.Open("north", 1, err));
    BOOST_REQUIRE_EQUAL(err, "FROZEN");
    BOOST_REQUIRE(plane.earned() == 0);
    BOOST_REQUIRE(!plane.has("north"));
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
