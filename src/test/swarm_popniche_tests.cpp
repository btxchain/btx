// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_popniche.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_popniche_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(a_worse_score_does_not_replace_the_niche)
{
    modelnet::SwarmPopNiche pop;
    std::string err;
    BOOST_CHECK(!pop.Place("", "a", 1, err));
    BOOST_CHECK_EQUAL(err, "NICHE");
    BOOST_REQUIRE(pop.Place("coding", "model-a", 10, err));
    BOOST_CHECK(!pop.Place("coding", "model-b", 9, err));
    BOOST_CHECK_EQUAL(err, "KEPT");
    BOOST_REQUIRE(pop.Place("coding", "model-c", 11, err));
    std::string id;
    int64_t quality = 0;
    BOOST_REQUIRE(pop.Occupy("coding", id, quality));
    BOOST_CHECK_EQUAL(id, "model-c");
    BOOST_CHECK_EQUAL(quality, 11);
}

BOOST_AUTO_TEST_CASE(niches_stay_separate)
{
    modelnet::SwarmPopNiche pop;
    std::string err;
    BOOST_REQUIRE(pop.Place("general", "base", 5, err));
    BOOST_REQUIRE(pop.Place("research", "trial", 1, err));
    BOOST_CHECK_EQUAL(pop.Niches().size(), 2U);
    std::string winner;
    BOOST_CHECK(!pop.SingleWinner(winner));
}

BOOST_AUTO_TEST_SUITE_END()
