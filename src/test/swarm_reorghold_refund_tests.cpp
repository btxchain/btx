// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_reorghold/swarm_reorghold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_reorghold_refund_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_refund_is_channel)
{
    modelnet::SwarmReorgHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("north", 40, err));
    BOOST_REQUIRE(plane.Open("south", 60, err));

    BOOST_REQUIRE(!plane.Refund("east", err));
    BOOST_REQUIRE_EQUAL(err, "CHANNEL");
    BOOST_REQUIRE(!plane.refund_built());
    BOOST_REQUIRE(plane.channels() == 2);
    BOOST_REQUIRE(plane.earned() == 100);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_CASE(refund_before_reorg_is_held_and_does_not_broadcast)
{
    modelnet::SwarmReorgHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("north", 40, err));
    BOOST_REQUIRE(plane.Open("south", 60, err));
    BOOST_REQUIRE(!plane.frozen());

    BOOST_REQUIRE(!plane.Refund("north", err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(!plane.refund_built());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(plane.has("north"));
    BOOST_REQUIRE(plane.has("south"));
    BOOST_REQUIRE(!plane.paid("north"));
    BOOST_REQUIRE(!plane.paid("south"));
    BOOST_REQUIRE(plane.channel_earned("north") == 40);
    BOOST_REQUIRE(plane.channel_earned("south") == 60);
    BOOST_REQUIRE(plane.earned() == 100);
    BOOST_REQUIRE(!plane.channel_frozen("north"));

    err = "prior";
    BOOST_REQUIRE(!plane.Refund("south", err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(!plane.refund_built());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(plane.earned() == 100);
    BOOST_REQUIRE(plane.channels() == 2);
}

BOOST_AUTO_TEST_CASE(refund_while_frozen_builds_nothing)
{
    modelnet::SwarmReorgHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("north", 40, err));
    BOOST_REQUIRE(plane.Open("south", 60, err));
    BOOST_REQUIRE(plane.Reorg(err));
    BOOST_REQUIRE(plane.earned() == 100);
    BOOST_REQUIRE(plane.frozen());
    BOOST_REQUIRE(!plane.broadcast());

    err = "prior";
    BOOST_REQUIRE(!plane.Refund("north", err));
    BOOST_REQUIRE_EQUAL(err, "FROZEN");
    BOOST_REQUIRE(!plane.refund_built());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(plane.has("north"));
    BOOST_REQUIRE(plane.has("south"));
    BOOST_REQUIRE(plane.channels() == 2);
    BOOST_REQUIRE(plane.channel_frozen("north"));
    BOOST_REQUIRE(plane.channel_frozen("south"));
    BOOST_REQUIRE(!plane.paid("north"));
    BOOST_REQUIRE(!plane.paid("south"));
    BOOST_REQUIRE(plane.channel_earned("north") == 40);
    BOOST_REQUIRE(plane.channel_earned("south") == 60);
    BOOST_REQUIRE(plane.earned() == 100);

    err = "prior";
    BOOST_REQUIRE(!plane.Refund("south", err));
    BOOST_REQUIRE_EQUAL(err, "FROZEN");
    BOOST_REQUIRE(!plane.refund_built());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(plane.earned() == 100);
    BOOST_REQUIRE(plane.frozen());

    err = "prior";
    BOOST_REQUIRE(!plane.Reorg(err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.earned() == 100);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
