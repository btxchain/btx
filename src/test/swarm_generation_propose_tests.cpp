// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/generation.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_generation_propose_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(propose_without_weakness_stores_nothing)
{
    modelnet::SwarmGenerationEngine gen;
    std::string err = "prior";

    BOOST_CHECK(!gen.Propose("exp", err));
    BOOST_CHECK_EQUAL(err, "NO_WEAKNESS");
    BOOST_CHECK_EQUAL(gen.proposal_count(), 0U);
    BOOST_CHECK_EQUAL(gen.weakness_count(), 0U);
}

BOOST_AUTO_TEST_CASE(propose_stores_on_the_frontier)
{
    modelnet::SwarmGenerationEngine gen;
    std::string err = "prior";

    BOOST_REQUIRE(gen.Identify("slow-decode", err));
    BOOST_CHECK(gen.Propose("try-recipe", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(gen.proposal_count(), 1U);
    BOOST_CHECK(gen.Propose("try-recipe", err));
    BOOST_CHECK_EQUAL(gen.proposal_count(), 2U);
}

BOOST_AUTO_TEST_SUITE_END()
