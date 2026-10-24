// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nicheslots/nicheslots.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_nicheslots_quiet_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bytes_moved_stay_zero)
{
    modelnet::SwarmNicheSlots plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.broadcast());

    BOOST_REQUIRE(plane.Open("general", 2, err));
    BOOST_REQUIRE(plane.Open("coding", 1, err));
    BOOST_REQUIRE(plane.Open("research", 1, err));
    BOOST_REQUIRE(plane.Spend("coding", "patch", err));
    BOOST_CHECK(!plane.Spend("coding", "patch", err));
    BOOST_CHECK(!plane.Spend("coding", "next", err));
    BOOST_CHECK(!plane.Move("patch", "coding", "research", err));
    BOOST_CHECK(!plane.Open("ops", 1, err));

    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE_EQUAL(plane.Remaining("coding"), 0);
    BOOST_REQUIRE_EQUAL(plane.Remaining("general"), 2);
    BOOST_REQUIRE_EQUAL(plane.Remaining("research"), 1);
    BOOST_REQUIRE_EQUAL(plane.tasks("coding").size(), 1U);
    BOOST_REQUIRE_EQUAL(plane.tasks("coding")[0], "patch");
    BOOST_REQUIRE(plane.tasks("research").empty());
    BOOST_REQUIRE(plane.tasks("general").empty());
}

BOOST_AUTO_TEST_SUITE_END()
