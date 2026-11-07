// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_forward/forward.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_forward_forward_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_channel_is_channel)
{
    modelnet::SwarmForward gate;
    std::string err = "prior";
    BOOST_REQUIRE(!gate.Forward("missing", "pay", 1, true, 1000, 1160, 800, err));
    BOOST_REQUIRE_EQUAL(err, "CHANNEL");
    BOOST_REQUIRE(!gate.opened("missing"));
    BOOST_REQUIRE(!gate.forwarded("missing", "pay"));
    BOOST_REQUIRE_EQUAL(gate.forward_count(), 0U);
    BOOST_REQUIRE_EQUAL(gate.remaining("missing"), 0);
}

BOOST_AUTO_TEST_CASE(empty_payment_and_low_amount_store_nothing)
{
    modelnet::SwarmForward gate;
    std::string err = "prior";
    BOOST_REQUIRE(gate.Open("ch", 50, err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!gate.Forward("ch", "", 10, true, 1000, 1160, 800, err));
    BOOST_REQUIRE_EQUAL(err, "PAYMENT");
    BOOST_REQUIRE(!gate.forwarded("ch", ""));
    BOOST_REQUIRE_EQUAL(gate.remaining("ch"), 50);
    BOOST_REQUIRE_EQUAL(gate.forward_count(), 0U);

    err = "prior";
    BOOST_REQUIRE(!gate.Forward("ch", "pay", 0, true, 1000, 1160, 800, err));
    BOOST_REQUIRE_EQUAL(err, "ATOMS");
    BOOST_REQUIRE_EQUAL(gate.remaining("ch"), 50);

    err = "prior";
    BOOST_REQUIRE(!gate.Forward("ch", "pay", -3, true, 1000, 1160, 800, err));
    BOOST_REQUIRE_EQUAL(err, "ATOMS");
    BOOST_REQUIRE(!gate.forwarded("ch", "pay"));
    BOOST_REQUIRE_EQUAL(gate.remaining("ch"), 50);
    BOOST_REQUIRE_EQUAL(gate.forward_count(), 0U);
}

BOOST_AUTO_TEST_CASE(short_liquidity_stays)
{
    modelnet::SwarmForward gate;
    std::string err = "prior";
    BOOST_REQUIRE(gate.Open("ch", 10, err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!gate.Forward("ch", "pay", 11, true, 1000, 1160, 800, err));
    BOOST_REQUIRE_EQUAL(err, "SHORT");
    BOOST_REQUIRE_EQUAL(gate.remaining("ch"), 10);
    BOOST_REQUIRE(!gate.forwarded("ch", "pay"));
    BOOST_REQUIRE_EQUAL(gate.forward_count(), 0U);
    BOOST_REQUIRE(gate.hops().empty());
}

BOOST_AUTO_TEST_CASE(margin_failure_stores_nothing)
{
    modelnet::SwarmForward gate;
    std::string err = "prior";
    BOOST_REQUIRE(gate.Open("ch", 40, err));
    BOOST_REQUIRE(err.empty());

    // outgoing 1159 is below incoming 1000 + 160. Height would still pass
    // SwarmForwardAllowed, and the incoming hop is committed.
    err = "prior";
    BOOST_REQUIRE(!gate.Forward("ch", "pay", 10, true, 1000, 1159, 800, err));
    BOOST_REQUIRE_EQUAL(err, "MARGIN");
    BOOST_REQUIRE_EQUAL(gate.remaining("ch"), 40);
    BOOST_REQUIRE(!gate.forwarded("ch", "pay"));
    BOOST_REQUIRE_EQUAL(gate.forward_count(), 0U);

    // Margin is decided before the commitment check.
    err = "prior";
    BOOST_REQUIRE(!gate.Forward("ch", "pay", 10, false, 1000, 1159, 800, err));
    BOOST_REQUIRE_EQUAL(err, "MARGIN");
    BOOST_REQUIRE_EQUAL(gate.remaining("ch"), 40);
    BOOST_REQUIRE_EQUAL(gate.forward_count(), 0U);
}

BOOST_AUTO_TEST_CASE(forward_allowed_refusal_stores_nothing)
{
    modelnet::SwarmForward gate;
    std::string err = "prior";
    BOOST_REQUIRE(gate.Open("ch", 40, err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!gate.Forward("ch", "pay", 10, false, 1000, 1160, 800, err));
    BOOST_REQUIRE_EQUAL(err, "COMMITMENT");
    BOOST_REQUIRE_EQUAL(gate.remaining("ch"), 40);
    BOOST_REQUIRE(!gate.forwarded("ch", "pay"));
    BOOST_REQUIRE_EQUAL(gate.forward_count(), 0U);

    err = "prior";
    BOOST_REQUIRE(!gate.Forward("ch", "pay", 10, true, 1000, 1160, 841, err));
    BOOST_REQUIRE_EQUAL(err, "EXPIRY");
    BOOST_REQUIRE_EQUAL(gate.remaining("ch"), 40);
    BOOST_REQUIRE(!gate.forwarded("ch", "pay"));
    BOOST_REQUIRE_EQUAL(gate.forward_count(), 0U);
}

BOOST_AUTO_TEST_CASE(one_successful_forward_then_replay)
{
    modelnet::SwarmForward gate;
    std::string err = "prior";
    BOOST_REQUIRE(gate.Open("ch", 100, err));
    BOOST_REQUIRE(err.empty());

    // outgoing 1160 is incoming 1000 + 160. height 840 meets the allow margin.
    BOOST_REQUIRE(gate.Forward("ch", "pay", 40, true, 1000, 1160, 840, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(gate.forwarded("ch", "pay"));
    BOOST_REQUIRE_EQUAL(gate.remaining("ch"), 60);
    BOOST_REQUIRE_EQUAL(gate.forward_count(), 1U);
    BOOST_REQUIRE_EQUAL(gate.hops().at(0).payment_id, "pay");
    BOOST_REQUIRE_EQUAL(gate.hops().at(0).amount, 40);
    BOOST_REQUIRE_EQUAL(gate.hops().at(0).outgoing_expiry, 1160);
    BOOST_REQUIRE(!gate.qualified());
    BOOST_REQUIRE(!gate.broadcast());
    BOOST_REQUIRE_EQUAL(gate.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(gate.automatic_spend(), "0");

    err = "prior";
    BOOST_REQUIRE(!gate.Forward("ch", "pay", 40, true, 1000, 1160, 840, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(gate.remaining("ch"), 60);
    BOOST_REQUIRE_EQUAL(gate.forward_count(), 1U);

    err = "prior";
    BOOST_REQUIRE(!gate.Forward("ch", "pay", 1000, true, 1000, 1160, 840, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(gate.remaining("ch"), 60);

    BOOST_REQUIRE(gate.Forward("ch", "pay-2", 60, true, 1000, 1200, 800, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(gate.remaining("ch"), 0);
    BOOST_REQUIRE(gate.forwarded("ch", "pay-2"));
    BOOST_REQUIRE_EQUAL(gate.forward_count(), 2U);

    err = "prior";
    BOOST_REQUIRE(!gate.Forward("ch", "pay-3", 1, true, 1000, 1160, 800, err));
    BOOST_REQUIRE_EQUAL(err, "SHORT");
    BOOST_REQUIRE_EQUAL(gate.remaining("ch"), 0);
    BOOST_REQUIRE(!gate.forwarded("ch", "pay-3"));
    BOOST_REQUIRE_EQUAL(gate.forward_count(), 2U);
}

BOOST_AUTO_TEST_CASE(same_payment_forwards_once_per_channel)
{
    modelnet::SwarmForward gate;
    std::string err = "prior";
    BOOST_REQUIRE(gate.Open("hop-a", 100, err));
    BOOST_REQUIRE(gate.Open("hop-b", 80, err));
    BOOST_REQUIRE(err.empty());

    BOOST_REQUIRE(gate.Forward("hop-a", "pay", 30, true, 2000, 2160, 1800, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(gate.Forward("hop-b", "pay", 30, true, 2160, 2320, 1800, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(gate.remaining("hop-a"), 70);
    BOOST_REQUIRE_EQUAL(gate.remaining("hop-b"), 50);
    BOOST_REQUIRE(gate.forwarded("hop-a", "pay"));
    BOOST_REQUIRE(gate.forwarded("hop-b", "pay"));
    BOOST_REQUIRE_EQUAL(gate.forward_count(), 2U);

    err = "prior";
    BOOST_REQUIRE(!gate.Forward("hop-a", "pay", 30, true, 2000, 2160, 1800, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(gate.remaining("hop-a"), 70);
    BOOST_REQUIRE_EQUAL(gate.remaining("hop-b"), 50);
    BOOST_REQUIRE_EQUAL(gate.forward_count(), 2U);
    BOOST_REQUIRE(!gate.qualified());
}

BOOST_AUTO_TEST_CASE(margin_refusal_can_be_retried)
{
    modelnet::SwarmForward gate;
    std::string err = "prior";
    BOOST_REQUIRE(gate.Open("ch", 25, err));
    BOOST_REQUIRE(!gate.Forward("ch", "pay", 5, true, 500, 659, 300, err));
    BOOST_REQUIRE_EQUAL(err, "MARGIN");
    BOOST_REQUIRE_EQUAL(gate.remaining("ch"), 25);

    BOOST_REQUIRE(gate.Forward("ch", "pay", 5, true, 500, 660, 300, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(gate.remaining("ch"), 20);
    BOOST_REQUIRE(gate.forwarded("ch", "pay"));
    BOOST_REQUIRE_EQUAL(gate.forward_count(), 1U);
    BOOST_REQUIRE(!gate.qualified());
    BOOST_REQUIRE(!gate.broadcast());
    BOOST_REQUIRE_EQUAL(gate.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(gate.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
