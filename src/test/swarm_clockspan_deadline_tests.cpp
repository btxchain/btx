// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_clockspan/limits.h>
#include <modelnet/swarm_clockspan/swarm_clockspan.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_clockspan_deadline_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(deadline_claim_mines_nothing_when_no_spacing_is_stored)
{
    modelnet::SwarmClockSpan plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.spacing() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);

    BOOST_REQUIRE(!plane.ClaimDeadline(err));
    BOOST_REQUIRE_EQUAL(err, "NOT_DEADLINE");
    BOOST_REQUIRE(!plane.noted());
    BOOST_REQUIRE(plane.spacing() == 0);
    BOOST_REQUIRE(plane.spacing() == modelnet::kSwarmClockSpanUnset);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.mined() == modelnet::kSwarmClockSpanMined);
    BOOST_REQUIRE(plane.blocks() == 0);
    BOOST_REQUIRE(plane.blocks() == modelnet::kSwarmClockSpanBlocks);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());

    err = "prior";
    BOOST_REQUIRE(!plane.ClaimDeadline(err));
    BOOST_REQUIRE_EQUAL(err, "NOT_DEADLINE");
    BOOST_REQUIRE(plane.spacing() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);
}

BOOST_AUTO_TEST_CASE(deadline_claim_mines_nothing_and_keeps_ninety)
{
    modelnet::SwarmClockSpan plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Note(int64_t{90}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.spacing() == 90);

    err = "prior";
    BOOST_REQUIRE(!plane.ClaimDeadline(err));
    BOOST_REQUIRE_EQUAL(err, "NOT_DEADLINE");
    BOOST_REQUIRE(plane.noted());
    BOOST_REQUIRE(plane.spacing() == 90);
    BOOST_REQUIRE(plane.spacing() == modelnet::kSwarmClockSpanSeconds);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());

    err = "prior";
    BOOST_REQUIRE(!plane.ClaimDeadline(err));
    BOOST_REQUIRE_EQUAL(err, "NOT_DEADLINE");
    BOOST_REQUIRE(plane.spacing() == 90);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Note(int64_t{90}, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.spacing() == 90);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);
}

BOOST_AUTO_TEST_CASE(deadline_claim_after_a_refused_spacing_stores_nothing)
{
    modelnet::SwarmClockSpan plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Note(int64_t{15}, err));
    BOOST_REQUIRE_EQUAL(err, "SPACING");

    err = "prior";
    BOOST_REQUIRE(!plane.ClaimDeadline(err));
    BOOST_REQUIRE_EQUAL(err, "NOT_DEADLINE");
    BOOST_REQUIRE(!plane.noted());
    BOOST_REQUIRE(plane.spacing() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_SUITE_END()
