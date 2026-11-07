// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nicheslots/nicheslots.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_nicheslots_spend_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_niche_spend_stores_nothing)
{
    modelnet::SwarmNicheSlots plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("general", 3, err));
    BOOST_CHECK(!plane.Spend("ops", "patch", err));
    BOOST_CHECK_EQUAL(err, "NICHE");
    BOOST_CHECK(!plane.Spend("", "patch", err));
    BOOST_CHECK_EQUAL(err, "NICHE");
    BOOST_CHECK(!plane.Spend("Coding", "patch", err));
    BOOST_CHECK_EQUAL(err, "NICHE");

    BOOST_CHECK(!plane.Spend("coding", "patch", err));
    BOOST_CHECK_EQUAL(err, "NICHE");
    BOOST_REQUIRE_EQUAL(plane.Remaining("coding"), -1);
    BOOST_REQUIRE(plane.tasks("coding").empty());

    BOOST_REQUIRE_EQUAL(plane.Remaining("general"), 3);
    BOOST_REQUIRE(plane.tasks("general").empty());
    BOOST_REQUIRE_EQUAL(plane.Remaining("research"), -1);
}

BOOST_AUTO_TEST_CASE(empty_task_stores_nothing)
{
    modelnet::SwarmNicheSlots plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("coding", 2, err));
    BOOST_CHECK(!plane.Spend("coding", "", err));
    BOOST_CHECK_EQUAL(err, "TASK");
    BOOST_REQUIRE_EQUAL(plane.Remaining("coding"), 2);
    BOOST_REQUIRE(plane.tasks("coding").empty());

    BOOST_CHECK(!plane.Spend("general", "", err));
    BOOST_CHECK_EQUAL(err, "TASK");
    BOOST_REQUIRE_EQUAL(plane.Remaining("general"), -1);

    BOOST_REQUIRE(plane.Spend("coding", "patch", err));
    BOOST_REQUIRE_EQUAL(plane.Remaining("coding"), 1);
    BOOST_CHECK(!plane.Spend("coding", "", err));
    BOOST_CHECK_EQUAL(err, "TASK");
    BOOST_REQUIRE_EQUAL(plane.Remaining("coding"), 1);
    const std::vector<std::string> tasks = plane.tasks("coding");
    BOOST_REQUIRE_EQUAL(tasks.size(), 1U);
    BOOST_REQUIRE_EQUAL(tasks[0], "patch");
}

BOOST_AUTO_TEST_CASE(spend_leaves_other_niches)
{
    modelnet::SwarmNicheSlots plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("general", 4, err));
    BOOST_REQUIRE(plane.Open("coding", 2, err));
    BOOST_REQUIRE(plane.Open("research", 3, err));

    BOOST_REQUIRE(plane.Spend("coding", "patch", err));
    BOOST_REQUIRE_EQUAL(plane.Remaining("coding"), 1);
    BOOST_REQUIRE_EQUAL(plane.Remaining("general"), 4);
    BOOST_REQUIRE_EQUAL(plane.Remaining("research"), 3);

    const std::vector<std::string> coding = plane.tasks("coding");
    BOOST_REQUIRE_EQUAL(coding.size(), 1U);
    BOOST_REQUIRE_EQUAL(coding[0], "patch");
    BOOST_REQUIRE(plane.tasks("general").empty());
    BOOST_REQUIRE(plane.tasks("research").empty());

    BOOST_REQUIRE(plane.Spend("research", "patch", err));
    BOOST_REQUIRE_EQUAL(plane.Remaining("research"), 2);
    BOOST_REQUIRE_EQUAL(plane.Remaining("coding"), 1);
    BOOST_REQUIRE_EQUAL(plane.Remaining("general"), 4);
    BOOST_REQUIRE_EQUAL(plane.tasks("research").size(), 1U);
    BOOST_REQUIRE_EQUAL(plane.tasks("research")[0], "patch");
    BOOST_REQUIRE_EQUAL(plane.tasks("coding").size(), 1U);

    BOOST_REQUIRE(plane.Spend("general", "notes", err));
    BOOST_REQUIRE(plane.Spend("coding", "review", err));
    BOOST_REQUIRE_EQUAL(plane.Remaining("general"), 3);
    BOOST_REQUIRE_EQUAL(plane.Remaining("coding"), 0);
    BOOST_REQUIRE_EQUAL(plane.Remaining("research"), 2);
    BOOST_REQUIRE_EQUAL(plane.tasks("general").size(), 1U);
    BOOST_REQUIRE_EQUAL(plane.tasks("general")[0], "notes");
    BOOST_REQUIRE_EQUAL(plane.tasks("coding").size(), 2U);
    BOOST_REQUIRE_EQUAL(plane.tasks("coding")[1], "review");
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_CASE(spend_exhausted_stores_nothing)
{
    modelnet::SwarmNicheSlots plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("general", 3, err));
    BOOST_REQUIRE(plane.Open("coding", 1, err));
    BOOST_REQUIRE(plane.Open("research", 2, err));

    BOOST_REQUIRE(plane.Spend("coding", "patch", err));
    BOOST_REQUIRE_EQUAL(plane.Remaining("coding"), 0);

    BOOST_CHECK(!plane.Spend("coding", "next", err));
    BOOST_CHECK_EQUAL(err, "EXHAUSTED");
    BOOST_REQUIRE_EQUAL(plane.Remaining("coding"), 0);
    BOOST_REQUIRE_EQUAL(plane.tasks("coding").size(), 1U);
    BOOST_REQUIRE_EQUAL(plane.tasks("coding")[0], "patch");
    BOOST_REQUIRE_EQUAL(plane.Remaining("general"), 3);
    BOOST_REQUIRE_EQUAL(plane.Remaining("research"), 2);
    BOOST_REQUIRE(plane.tasks("general").empty());
    BOOST_REQUIRE(plane.tasks("research").empty());

    BOOST_REQUIRE(plane.Spend("research", "read", err));
    BOOST_REQUIRE(plane.Spend("research", "write", err));
    BOOST_REQUIRE_EQUAL(plane.Remaining("research"), 0);
    BOOST_CHECK(!plane.Spend("research", "extra", err));
    BOOST_CHECK_EQUAL(err, "EXHAUSTED");
    BOOST_REQUIRE_EQUAL(plane.Remaining("research"), 0);
    BOOST_REQUIRE_EQUAL(plane.tasks("research").size(), 2U);
    BOOST_REQUIRE_EQUAL(plane.Remaining("general"), 3);
    BOOST_REQUIRE_EQUAL(plane.Remaining("coding"), 0);
}

BOOST_AUTO_TEST_CASE(spend_replay_does_not_decrement)
{
    modelnet::SwarmNicheSlots plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("general", 3, err));
    BOOST_REQUIRE(plane.Open("coding", 2, err));

    BOOST_REQUIRE(plane.Spend("coding", "patch", err));
    BOOST_CHECK(!plane.Spend("coding", "patch", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.Remaining("coding"), 1);
    BOOST_REQUIRE_EQUAL(plane.tasks("coding").size(), 1U);
    BOOST_REQUIRE_EQUAL(plane.tasks("coding")[0], "patch");
    BOOST_REQUIRE_EQUAL(plane.Remaining("general"), 3);

    BOOST_REQUIRE(plane.Spend("coding", "review", err));
    BOOST_REQUIRE_EQUAL(plane.Remaining("coding"), 0);
    BOOST_CHECK(!plane.Spend("coding", "patch", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.Remaining("coding"), 0);
    BOOST_REQUIRE_EQUAL(plane.tasks("coding").size(), 2U);
    BOOST_REQUIRE_EQUAL(plane.Remaining("general"), 3);
    BOOST_REQUIRE(plane.tasks("general").empty());

    BOOST_REQUIRE(plane.Spend("general", "patch", err));
    BOOST_REQUIRE_EQUAL(plane.Remaining("general"), 2);
    BOOST_REQUIRE_EQUAL(plane.Remaining("coding"), 0);
    BOOST_CHECK(!plane.Spend("general", "patch", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.Remaining("general"), 2);
    BOOST_REQUIRE_EQUAL(plane.tasks("general").size(), 1U);
}

BOOST_AUTO_TEST_SUITE_END()
