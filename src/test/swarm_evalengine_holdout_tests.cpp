// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalengine/engine.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_evalengine_holdout_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(visible_holdout_is_refused_and_stores_nothing)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    BOOST_REQUIRE(engine.OpenExperiment("exp", err));
    BOOST_REQUIRE(engine.BindCandidate("exp", "cand", err));
    BOOST_REQUIRE(engine.CommitSuite("exp", "suite", err));
    BOOST_CHECK(!engine.Report("exp", "cand", "author", "eval", "da", "de", true, false, false, err));
    BOOST_CHECK_EQUAL(err, "HOLDOUT");
    BOOST_CHECK_EQUAL(engine.report_count("cand"), std::size_t{0});
    BOOST_CHECK_EQUAL(engine.regression_count("cand"), std::size_t{0});
    BOOST_CHECK(!engine.qualified("cand"));
}

BOOST_AUTO_TEST_CASE(holdout_does_not_replace_an_earlier_refusal)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    BOOST_REQUIRE(engine.OpenExperiment("exp", err));
    BOOST_REQUIRE(engine.BindCandidate("exp", "cand", err));
    BOOST_REQUIRE(engine.CommitSuite("exp", "suite", err));
    BOOST_CHECK(!engine.Report("exp", "cand", "author", "eval", "lab", "lab", true, true, false, err));
    BOOST_CHECK_EQUAL(err, "NOT_QUORUM");
    BOOST_CHECK_EQUAL(engine.regression_count("cand"), std::size_t{0});
}

BOOST_AUTO_TEST_CASE(holdout_beats_a_safety_flag_and_stores_nothing)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    BOOST_REQUIRE(engine.OpenExperiment("exp", err));
    BOOST_REQUIRE(engine.BindCandidate("exp", "cand", err));
    BOOST_REQUIRE(engine.CommitSuite("exp", "suite", err));
    BOOST_CHECK(!engine.Report("exp", "cand", "author", "eval", "da", "de", true, true, true, err));
    BOOST_CHECK_EQUAL(err, "HOLDOUT");
    BOOST_CHECK_EQUAL(engine.report_count("cand"), std::size_t{0});
    BOOST_CHECK_EQUAL(engine.regression_count("cand"), std::size_t{0});
}

BOOST_AUTO_TEST_CASE(hidden_holdout_can_still_be_an_accepting_report)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    BOOST_REQUIRE(engine.OpenExperiment("exp", err));
    BOOST_REQUIRE(engine.BindCandidate("exp", "cand", err));
    BOOST_REQUIRE(engine.CommitSuite("exp", "suite", err));
    BOOST_REQUIRE(engine.Report("exp", "cand", "author-a", "eval-a", "da", "lab-a", false, false, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!engine.Report("exp", "cand", "author-b", "eval-b", "db", "lab-b", true, false, false, err));
    BOOST_CHECK_EQUAL(err, "HOLDOUT");
    BOOST_CHECK_EQUAL(engine.report_count("cand"), std::size_t{1});
    BOOST_CHECK(!engine.qualified("cand"));
    BOOST_REQUIRE(engine.Report("exp", "cand", "author-c", "eval-c", "dc", "lab-c", false, false, false, err));
    BOOST_CHECK_EQUAL(engine.report_count("cand"), std::size_t{2});
    BOOST_CHECK(engine.qualified("cand"));
}

BOOST_AUTO_TEST_SUITE_END()
