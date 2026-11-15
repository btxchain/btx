// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nicheslots/nicheslots.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_nicheslots_open_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_niche_stores_nothing)
{
    modelnet::SwarmNicheSlots plane;
    std::string err = "prior";

    BOOST_CHECK(!plane.Open("ops", 3, err));
    BOOST_CHECK_EQUAL(err, "NICHE");
    BOOST_REQUIRE_EQUAL(plane.Remaining("ops"), -1);
    BOOST_REQUIRE(plane.tasks("ops").empty());

    BOOST_CHECK(!plane.Open("", 3, err));
    BOOST_CHECK_EQUAL(err, "NICHE");
    BOOST_CHECK(!plane.Open("General", 2, err));
    BOOST_CHECK_EQUAL(err, "NICHE");
    BOOST_CHECK(!plane.Open("coding ", 2, err));
    BOOST_CHECK_EQUAL(err, "NICHE");
    BOOST_CHECK(!plane.Open("generalcoding", 2, err));
    BOOST_CHECK_EQUAL(err, "NICHE");

    BOOST_REQUIRE_EQUAL(plane.Remaining("general"), -1);
    BOOST_REQUIRE_EQUAL(plane.Remaining("coding"), -1);
    BOOST_REQUIRE_EQUAL(plane.Remaining("research"), -1);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.broadcast());

    BOOST_REQUIRE(plane.Open("general", 4, err));
    BOOST_CHECK(!plane.Open("research-lab", 1, err));
    BOOST_CHECK_EQUAL(err, "NICHE");
    BOOST_REQUIRE_EQUAL(plane.Remaining("general"), 4);
    BOOST_REQUIRE_EQUAL(plane.Remaining("research"), -1);
    BOOST_REQUIRE(plane.tasks("general").empty());
}

BOOST_AUTO_TEST_CASE(slots_below_one_store_nothing)
{
    modelnet::SwarmNicheSlots plane;
    std::string err = "prior";

    BOOST_CHECK(!plane.Open("coding", 0, err));
    BOOST_CHECK_EQUAL(err, "SLOTS");
    BOOST_REQUIRE_EQUAL(plane.Remaining("coding"), -1);
    BOOST_REQUIRE(plane.tasks("coding").empty());

    BOOST_CHECK(!plane.Open("coding", -1, err));
    BOOST_CHECK_EQUAL(err, "SLOTS");
    BOOST_REQUIRE_EQUAL(plane.Remaining("coding"), -1);

    BOOST_CHECK(!plane.Open("general", 0, err));
    BOOST_CHECK_EQUAL(err, "SLOTS");
    BOOST_REQUIRE_EQUAL(plane.Remaining("general"), -1);
    BOOST_REQUIRE_EQUAL(plane.Remaining("research"), -1);

    BOOST_REQUIRE(plane.Open("coding", 2, err));
    BOOST_REQUIRE_EQUAL(plane.Remaining("coding"), 2);
    BOOST_REQUIRE(plane.tasks("coding").empty());
    BOOST_REQUIRE_EQUAL(plane.Remaining("general"), -1);
}

BOOST_AUTO_TEST_CASE(second_open_is_replay)
{
    modelnet::SwarmNicheSlots plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("research", 5, err));
    BOOST_REQUIRE_EQUAL(plane.Remaining("research"), 5);

    BOOST_CHECK(!plane.Open("research", 9, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.Remaining("research"), 5);
    BOOST_REQUIRE(plane.tasks("research").empty());

    BOOST_CHECK(!plane.Open("research", 0, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.Remaining("research"), 5);

    BOOST_REQUIRE(plane.Open("general", 1, err));
    BOOST_REQUIRE_EQUAL(plane.Remaining("general"), 1);
    BOOST_REQUIRE_EQUAL(plane.Remaining("coding"), -1);
    BOOST_REQUIRE_EQUAL(plane.Remaining("research"), 5);
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_SUITE_END()
