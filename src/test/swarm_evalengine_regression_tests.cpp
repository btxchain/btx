// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalengine/engine.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <string>

namespace {

void BindSuite(modelnet::SwarmEvaluationEngine& engine, const std::string& candidate)
{
    std::string err;
    BOOST_REQUIRE(engine.OpenExperiment("exp", err));
    BOOST_REQUIRE(engine.BindCandidate("exp", candidate, err));
    BOOST_REQUIRE(engine.CommitSuite("exp", "suite", err));
}

void TwoAccepting(modelnet::SwarmEvaluationEngine& engine, const std::string& candidate)
{
    std::string err;
    BOOST_REQUIRE(engine.Report("exp", candidate, "author-a", "eval-a", "da", "lab-a", false, false, false, err));
    BOOST_REQUIRE(engine.Report("exp", candidate, "author-b", "eval-b", "db", "lab-b", false, false, false, err));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_evalengine_regression_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(safety_stores_a_regression_and_blocks_qualification)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    BindSuite(engine, "cand");
    TwoAccepting(engine, "cand");
    BOOST_CHECK(engine.qualified("cand"));
    BOOST_CHECK(!engine.Report("exp", "cand", "author-s", "eval-s", "ds", "lab-s", false, true, false, err));
    BOOST_CHECK_EQUAL(err, "SAFETY");
    BOOST_CHECK_EQUAL(engine.report_count("cand"), std::size_t{2});
    BOOST_CHECK_EQUAL(engine.regression_count("cand"), std::size_t{1});
    BOOST_CHECK(!engine.qualified("cand"));
    BOOST_CHECK(!engine.Promote("cand", err));
    BOOST_CHECK_EQUAL(err, "REGRESSION");
    BOOST_CHECK(!engine.promoted("cand"));
}

BOOST_AUTO_TEST_CASE(broad_regression_stores_a_regression_report)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    BindSuite(engine, "cand");
    BOOST_CHECK(!engine.Report("exp", "cand", "author", "eval", "da", "de", false, false, true, err));
    BOOST_CHECK_EQUAL(err, "REGRESSION");
    BOOST_CHECK_EQUAL(engine.report_count("cand"), std::size_t{0});
    BOOST_CHECK_EQUAL(engine.regression_count("cand"), std::size_t{1});
    BOOST_CHECK(!engine.qualified("cand"));
    BOOST_CHECK(!engine.Promote("cand", err));
    BOOST_CHECK_EQUAL(err, "REGRESSION");
}

BOOST_AUTO_TEST_CASE(safety_wins_when_both_regression_flags_are_set)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    BindSuite(engine, "cand");
    BOOST_CHECK(!engine.Report("exp", "cand", "author", "eval", "da", "de", false, true, true, err));
    BOOST_CHECK_EQUAL(err, "SAFETY");
    BOOST_CHECK_EQUAL(engine.regression_count("cand"), std::size_t{1});
    BOOST_CHECK_EQUAL(engine.report_count("cand"), std::size_t{0});
}

BOOST_AUTO_TEST_CASE(promoting_a_clean_candidate_keeps_the_other_regression)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    BOOST_REQUIRE(engine.OpenExperiment("exp", err));
    BOOST_REQUIRE(engine.BindCandidate("exp", "unsafe", err));
    BOOST_REQUIRE(engine.BindCandidate("exp", "clean", err));
    BOOST_REQUIRE(engine.CommitSuite("exp", "suite", err));
    TwoAccepting(engine, "unsafe");
    BOOST_CHECK(engine.qualified("unsafe"));
    BOOST_CHECK(!engine.Report("exp", "unsafe", "author-s", "eval-s", "ds", "lab-s", false, true, false, err));
    BOOST_CHECK_EQUAL(err, "SAFETY");
    BOOST_CHECK_EQUAL(engine.regression_count("unsafe"), std::size_t{1});

    BOOST_REQUIRE(engine.Report("exp", "clean", "author-a", "eval-a", "da", "lab-a", false, false, false, err));
    BOOST_REQUIRE(engine.Report("exp", "clean", "author-b", "eval-b", "db", "lab-b", false, false, false, err));
    BOOST_CHECK(engine.qualified("clean"));
    BOOST_REQUIRE(engine.Promote("clean", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(engine.promoted("clean"));
    BOOST_CHECK(!engine.promoted("unsafe"));
    BOOST_CHECK_EQUAL(engine.regression_count("unsafe"), std::size_t{1});
    BOOST_CHECK(!engine.qualified("unsafe"));
    BOOST_CHECK(!engine.Promote("unsafe", err));
    BOOST_CHECK_EQUAL(err, "REGRESSION");
    BOOST_CHECK_EQUAL(engine.report_count("unsafe"), std::size_t{2});
    BOOST_CHECK(engine.qualified("clean"));
    BOOST_CHECK(!engine.realm_promoted());
    BOOST_CHECK(!engine.exact_replay_admitted());
    BOOST_CHECK(!engine.money());
}

BOOST_AUTO_TEST_SUITE_END()
