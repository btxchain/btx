// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_forward/forward.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_forward_open_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_is_channel_and_stores_nothing)
{
    modelnet::SwarmForward gate;
    std::string err = "prior";
    BOOST_REQUIRE(!gate.Open("", 40, err));
    BOOST_REQUIRE_EQUAL(err, "CHANNEL");
    BOOST_REQUIRE(!gate.opened(""));
    BOOST_REQUIRE_EQUAL(gate.remaining(""), 0);
    BOOST_REQUIRE_EQUAL(gate.forward_count(), 0U);
    BOOST_REQUIRE(!gate.qualified());
    BOOST_REQUIRE(!gate.broadcast());
    BOOST_REQUIRE_EQUAL(gate.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(gate.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(liquidity_below_one_is_liquidity)
{
    modelnet::SwarmForward gate;
    std::string err = "prior";
    BOOST_REQUIRE(!gate.Open("ch", 0, err));
    BOOST_REQUIRE_EQUAL(err, "LIQUIDITY");
    BOOST_REQUIRE(!gate.opened("ch"));
    BOOST_REQUIRE_EQUAL(gate.remaining("ch"), 0);

    err = "prior";
    BOOST_REQUIRE(!gate.Open("ch", -5, err));
    BOOST_REQUIRE_EQUAL(err, "LIQUIDITY");
    BOOST_REQUIRE(!gate.opened("ch"));

    err = "prior";
    BOOST_REQUIRE(!gate.Open("", 0, err));
    BOOST_REQUIRE_EQUAL(err, "CHANNEL");
    BOOST_REQUIRE(!gate.opened(""));
}

BOOST_AUTO_TEST_CASE(second_open_is_replay_and_keeps_first_liquidity)
{
    modelnet::SwarmForward gate;
    std::string err = "prior";
    BOOST_REQUIRE(gate.Open("ch", 40, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(gate.opened("ch"));
    BOOST_REQUIRE_EQUAL(gate.remaining("ch"), 40);

    err = "prior";
    BOOST_REQUIRE(!gate.Open("ch", 99, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(gate.remaining("ch"), 40);

    err = "prior";
    BOOST_REQUIRE(!gate.Open("ch", 0, err));
    BOOST_REQUIRE_EQUAL(err, "LIQUIDITY");
    BOOST_REQUIRE_EQUAL(gate.remaining("ch"), 40);

    err = "prior";
    BOOST_REQUIRE(gate.Open("other", 7, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(gate.remaining("other"), 7);
    BOOST_REQUIRE_EQUAL(gate.remaining("ch"), 40);
    BOOST_REQUIRE(!gate.qualified());
    BOOST_REQUIRE(!gate.broadcast());
    BOOST_REQUIRE_EQUAL(gate.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(gate.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
