// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_clockspan/limits.h>
#include <modelnet/swarm_clockspan/swarm_clockspan.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void RequireQuiet(const modelnet::SwarmClockSpan& plane)
{
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmClockSpanBytesMoved);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(plane.broadcast() == modelnet::kSwarmClockSpanBroadcast);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_clockspan_bytes_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bytes_stay_zero_across_note_refusal_replay_and_deadline)
{
    modelnet::SwarmClockSpan plane;
    std::string err = "prior";

    RequireQuiet(plane);
    BOOST_REQUIRE(plane.spacing() == 0);

    BOOST_REQUIRE(!plane.Note(int64_t{0}, err));
    BOOST_REQUIRE_EQUAL(err, "RANGE");
    RequireQuiet(plane);
    BOOST_REQUIRE(plane.spacing() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Note(int64_t{12}, err));
    BOOST_REQUIRE_EQUAL(err, "SPACING");
    RequireQuiet(plane);
    BOOST_REQUIRE(plane.spacing() == 0);

    err = "prior";
    BOOST_REQUIRE(plane.Note(int64_t{90}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.spacing() == 90);
    RequireQuiet(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Note(int64_t{90}, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.spacing() == 90);
    RequireQuiet(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.ClaimDeadline(err));
    BOOST_REQUIRE_EQUAL(err, "NOT_DEADLINE");
    BOOST_REQUIRE(plane.spacing() == 90);
    RequireQuiet(plane);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_SUITE_END()
