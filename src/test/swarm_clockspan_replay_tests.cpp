// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_clockspan/replay.h>
#include <modelnet/swarm_clockspan/swarm_clockspan.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_clockspan_replay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(second_note_of_ninety_is_replay)
{
    modelnet::SwarmClockSpan plane;
    std::string err = "prior";

    BOOST_REQUIRE(!modelnet::SwarmClockSpanIsReplay(modelnet::SwarmClockSpanBook{}, int64_t{90}));

    BOOST_REQUIRE(plane.Note(int64_t{90}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.noted());
    BOOST_REQUIRE(plane.spacing() == 90);

    err = "prior";
    BOOST_REQUIRE(!plane.Note(int64_t{90}, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.noted());
    BOOST_REQUIRE(plane.spacing() == 90);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());

    err = "prior";
    BOOST_REQUIRE(!plane.Note(int64_t{90}, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.spacing() == 90);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);
}

BOOST_AUTO_TEST_CASE(range_and_spacing_are_decided_before_replay)
{
    modelnet::SwarmClockSpan plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Note(int64_t{90}, err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Note(int64_t{0}, err));
    BOOST_REQUIRE_EQUAL(err, "RANGE");
    BOOST_REQUIRE(plane.spacing() == 90);

    err = "prior";
    BOOST_REQUIRE(!plane.Note(int64_t{45}, err));
    BOOST_REQUIRE_EQUAL(err, "SPACING");
    BOOST_REQUIRE(plane.spacing() == 90);

    err = "prior";
    BOOST_REQUIRE(!plane.Note(int64_t{90}, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.noted());
    BOOST_REQUIRE(plane.spacing() == 90);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_SUITE_END()
