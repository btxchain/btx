// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nicheslots/nicheslots.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_nicheslots_move_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(move_across_niches_is_refused)
{
    modelnet::SwarmNicheSlots plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("general", 4, err));
    BOOST_REQUIRE(plane.Open("coding", 2, err));
    BOOST_REQUIRE(plane.Open("research", 3, err));
    BOOST_REQUIRE(plane.Spend("coding", "patch", err));
    BOOST_REQUIRE(plane.Spend("general", "notes", err));

    const int64_t general_left = plane.Remaining("general");
    const int64_t coding_left = plane.Remaining("coding");
    const int64_t research_left = plane.Remaining("research");

    BOOST_CHECK(!plane.Move("patch", "coding", "general", err));
    BOOST_CHECK_EQUAL(err, "NOT_MERGED");
    BOOST_REQUIRE_EQUAL(plane.Remaining("general"), general_left);
    BOOST_REQUIRE_EQUAL(plane.Remaining("coding"), coding_left);
    BOOST_REQUIRE_EQUAL(plane.Remaining("research"), research_left);

    const std::vector<std::string> general = plane.tasks("general");
    const std::vector<std::string> coding = plane.tasks("coding");
    BOOST_REQUIRE_EQUAL(general.size(), 1U);
    BOOST_REQUIRE_EQUAL(general[0], "notes");
    BOOST_REQUIRE_EQUAL(coding.size(), 1U);
    BOOST_REQUIRE_EQUAL(coding[0], "patch");
    BOOST_REQUIRE(plane.tasks("research").empty());

    BOOST_CHECK(!plane.Move("patch", "coding", "research", err));
    BOOST_CHECK_EQUAL(err, "NOT_MERGED");
    BOOST_REQUIRE_EQUAL(plane.Remaining("coding"), coding_left);
    BOOST_REQUIRE_EQUAL(plane.Remaining("research"), research_left);
    BOOST_REQUIRE(plane.tasks("research").empty());
    BOOST_REQUIRE_EQUAL(plane.tasks("coding").size(), 1U);

    BOOST_CHECK(!plane.Move("notes", "general", "general", err));
    BOOST_CHECK_EQUAL(err, "NOT_MERGED");
    BOOST_REQUIRE_EQUAL(plane.Remaining("general"), general_left);
    BOOST_REQUIRE_EQUAL(plane.tasks("general").size(), 1U);

    BOOST_CHECK(!plane.Move("missing", "research", "coding", err));
    BOOST_CHECK_EQUAL(err, "NOT_MERGED");
    BOOST_REQUIRE_EQUAL(plane.Remaining("research"), research_left);
    BOOST_REQUIRE_EQUAL(plane.Remaining("coding"), coding_left);

    BOOST_CHECK(!plane.Move("patch", "ops", "coding", err));
    BOOST_CHECK_EQUAL(err, "NOT_MERGED");
    BOOST_REQUIRE_EQUAL(plane.Remaining("ops"), -1);
    BOOST_REQUIRE_EQUAL(plane.Remaining("coding"), coding_left);
    BOOST_REQUIRE_EQUAL(plane.Remaining("general"), general_left);

    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_SUITE_END()
