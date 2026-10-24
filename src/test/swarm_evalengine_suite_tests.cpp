// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalengine/engine.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_evalengine_suite_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_experiment_stores_nothing)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    BOOST_CHECK(!engine.OpenExperiment("", err));
    BOOST_CHECK_EQUAL(err, "EXPERIMENT");
    BOOST_CHECK_EQUAL(engine.experiment_count(), std::size_t{0});
    BOOST_CHECK(engine.suite("").empty());
}

BOOST_AUTO_TEST_CASE(duplicate_experiment_keeps_the_first)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    BOOST_REQUIRE(engine.OpenExperiment("exp", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(engine.experiment_count(), std::size_t{1});
    BOOST_CHECK(!engine.OpenExperiment("exp", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(engine.experiment_count(), std::size_t{1});
    BOOST_REQUIRE(engine.OpenExperiment("exp-b", err));
    BOOST_CHECK_EQUAL(engine.experiment_count(), std::size_t{2});
}

BOOST_AUTO_TEST_CASE(bind_refuses_unknown_experiment_and_empty_candidate)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    BOOST_CHECK(!engine.BindCandidate("missing", "cand", err));
    BOOST_CHECK_EQUAL(err, "EXPERIMENT");
    BOOST_REQUIRE(engine.OpenExperiment("exp", err));
    BOOST_CHECK(!engine.BindCandidate("exp", "", err));
    BOOST_CHECK_EQUAL(err, "CANDIDATE");
    BOOST_REQUIRE(engine.BindCandidate("exp", "cand", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!engine.BindCandidate("exp", "cand", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(engine.BindCandidate("exp", "other", err));
}

BOOST_AUTO_TEST_CASE(second_suite_keeps_the_first)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    BOOST_CHECK(!engine.CommitSuite("missing", "suite-a", err));
    BOOST_CHECK_EQUAL(err, "EXPERIMENT");
    BOOST_REQUIRE(engine.OpenExperiment("exp", err));
    BOOST_CHECK(!engine.CommitSuite("exp", "", err));
    BOOST_CHECK_EQUAL(err, "SUITE");
    BOOST_CHECK(engine.suite("exp").empty());
    BOOST_REQUIRE(engine.CommitSuite("exp", "suite-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(engine.suite("exp"), "suite-a");
    BOOST_CHECK(!engine.CommitSuite("exp", "suite-b", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(engine.suite("exp"), "suite-a");
    BOOST_CHECK(!engine.CommitSuite("exp", "suite-a", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(engine.suite("exp"), "suite-a");
    BOOST_CHECK(!engine.OpenExperiment("exp", err));
    BOOST_CHECK_EQUAL(engine.suite("exp"), "suite-a");
}

BOOST_AUTO_TEST_CASE(suites_are_per_experiment)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err;
    BOOST_REQUIRE(engine.OpenExperiment("exp-a", err));
    BOOST_REQUIRE(engine.OpenExperiment("exp-b", err));
    BOOST_REQUIRE(engine.CommitSuite("exp-a", "suite-a", err));
    BOOST_REQUIRE(engine.CommitSuite("exp-b", "suite-b", err));
    BOOST_CHECK_EQUAL(engine.suite("exp-a"), "suite-a");
    BOOST_CHECK_EQUAL(engine.suite("exp-b"), "suite-b");
    BOOST_CHECK(engine.suite("missing").empty());
}

BOOST_AUTO_TEST_CASE(report_before_suite_stores_nothing)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    BOOST_REQUIRE(engine.OpenExperiment("exp", err));
    BOOST_REQUIRE(engine.BindCandidate("exp", "cand", err));
    BOOST_CHECK(!engine.Report("exp", "cand", "author", "eval", "da", "de", false, true, true, err));
    BOOST_CHECK_EQUAL(err, "NOT_PRECOMMITTED");
    BOOST_CHECK_EQUAL(engine.report_count("cand"), std::size_t{0});
    BOOST_CHECK_EQUAL(engine.regression_count("cand"), std::size_t{0});
    BOOST_CHECK(!engine.qualified("cand"));
    BOOST_CHECK(!engine.launched());
    BOOST_CHECK(!engine.gpu());
    BOOST_CHECK_EQUAL(engine.bytes_moved(), std::uint64_t{0});
    BOOST_CHECK_EQUAL(engine.atoms_moved(), std::uint64_t{0});
    BOOST_CHECK_EQUAL(engine.automatic_spend(), "0");
    BOOST_CHECK(!engine.broadcast());
    BOOST_CHECK(!engine.realm_promoted());
    BOOST_CHECK(!engine.exact_replay_admitted());
    BOOST_CHECK(!engine.money());
}

BOOST_AUTO_TEST_SUITE_END()
