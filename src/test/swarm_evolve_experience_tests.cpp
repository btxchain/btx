// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evolve/generation.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_evolve_experience_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(only_public_and_synthetic_trajectories_are_stored)
{
    modelnet::SwarmGeneration gen("subject-a", "baseline-parent", "coordinator-1");
    std::string err = "prior";
    BOOST_CHECK(!gen.Experience("prompt", "secret", err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(gen.ExperienceSize(), 0U);
    BOOST_CHECK(!gen.Experience("repository", "tree", err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!gen.Experience("credential", "key", err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!gen.Experience("", "empty", err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(gen.ExperienceSize(), 0U);

    BOOST_REQUIRE(gen.Experience("public_trajectory", "pub-body", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!gen.Experience("weights", "blob", err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_REQUIRE(gen.Experience("synthetic_trajectory", "syn-body", err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK_EQUAL(gen.ExperienceSize(), 2U);
    BOOST_REQUIRE_EQUAL(gen.ExperienceItems().size(), 2U);
    BOOST_CHECK_EQUAL(gen.ExperienceItems()[0].kind, "public_trajectory");
    BOOST_CHECK_EQUAL(gen.ExperienceItems()[0].body, "pub-body");
    BOOST_CHECK_EQUAL(gen.ExperienceItems()[1].kind, "synthetic_trajectory");
    BOOST_CHECK_EQUAL(gen.ExperienceItems()[1].body, "syn-body");
}

BOOST_AUTO_TEST_SUITE_END()
