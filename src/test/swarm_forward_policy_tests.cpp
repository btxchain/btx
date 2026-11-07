// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_forward/forward.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_forward_policy_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(qualified_stays_false)
{
    modelnet::SwarmForward gate;
    BOOST_REQUIRE(!gate.qualified());
    BOOST_REQUIRE(!gate.broadcast());
    BOOST_REQUIRE_EQUAL(gate.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(gate.automatic_spend(), "0");

    std::string err = "prior";
    BOOST_REQUIRE(gate.Open("ch", 20, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(gate.Forward("ch", "pay", 4, true, 1000, 1160, 800, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(gate.remaining("ch"), 16);
    BOOST_REQUIRE_EQUAL(gate.forward_count(), 1U);

    BOOST_REQUIRE(!gate.qualified());
    BOOST_REQUIRE(!gate.broadcast());
    BOOST_REQUIRE_EQUAL(gate.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(gate.automatic_spend(), "0");
    BOOST_REQUIRE(gate.hops().at(0).incoming_committed);
    BOOST_REQUIRE_EQUAL(gate.hops().at(0).channel, "ch");
}

BOOST_AUTO_TEST_SUITE_END()
