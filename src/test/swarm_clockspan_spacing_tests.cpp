// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_clockspan/swarm_clockspan.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_clockspan_spacing_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(other_positive_seconds_are_spacing_and_store_nothing)
{
    modelnet::SwarmClockSpan plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Note(int64_t{1}, err));
    BOOST_REQUIRE_EQUAL(err, "SPACING");
    BOOST_REQUIRE(!plane.noted());
    BOOST_REQUIRE(plane.spacing() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Note(int64_t{89}, err));
    BOOST_REQUIRE_EQUAL(err, "SPACING");
    BOOST_REQUIRE(plane.spacing() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Note(int64_t{91}, err));
    BOOST_REQUIRE_EQUAL(err, "SPACING");
    BOOST_REQUIRE(plane.spacing() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Note(int64_t{180}, err));
    BOOST_REQUIRE_EQUAL(err, "SPACING");
    BOOST_REQUIRE(!plane.noted());
    BOOST_REQUIRE(plane.spacing() == 0);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_CASE(another_spacing_after_ninety_keeps_the_first)
{
    modelnet::SwarmClockSpan plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Note(int64_t{90}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.spacing() == 90);

    err = "prior";
    BOOST_REQUIRE(!plane.Note(int64_t{60}, err));
    BOOST_REQUIRE_EQUAL(err, "SPACING");
    BOOST_REQUIRE(plane.noted());
    BOOST_REQUIRE(plane.spacing() == 90);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Note(INT64_MAX, err));
    BOOST_REQUIRE_EQUAL(err, "SPACING");
    BOOST_REQUIRE(plane.spacing() == 90);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_CASE(refused_spacing_does_not_block_a_later_ninety)
{
    modelnet::SwarmClockSpan plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Note(int64_t{30}, err));
    BOOST_REQUIRE_EQUAL(err, "SPACING");
    BOOST_REQUIRE(plane.spacing() == 0);

    err = "prior";
    BOOST_REQUIRE(plane.Note(int64_t{90}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.noted());
    BOOST_REQUIRE(plane.spacing() == 90);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.blocks() == 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_SUITE_END()
