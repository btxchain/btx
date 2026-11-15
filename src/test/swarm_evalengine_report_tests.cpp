// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalengine/engine.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <string>

namespace {

bool OpenBound(modelnet::SwarmEvaluationEngine& engine, const std::string& experiment, const std::string& candidate)
{
    std::string err;
    if (!engine.OpenExperiment(experiment, err)) {
        return false;
    }
    if (!engine.BindCandidate(experiment, candidate, err)) {
        return false;
    }
    return engine.CommitSuite(experiment, "suite", err);
}

bool Accepting(modelnet::SwarmEvaluationEngine& engine,
               const std::string& experiment,
               const std::string& candidate,
               const std::string& author,
               const std::string& evaluator,
               const std::string& author_domain,
               const std::string& evaluator_domain,
               std::string& err)
{
    return engine.Report(experiment, candidate, author, evaluator, author_domain, evaluator_domain, false, false, false, err);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_evalengine_report_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_experiment_or_unbound_candidate_is_candidate)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    BOOST_CHECK(!engine.Report("missing", "cand", "author", "eval", "da", "de", false, false, false, err));
    BOOST_CHECK_EQUAL(err, "CANDIDATE");
    BOOST_REQUIRE(engine.OpenExperiment("exp", err));
    BOOST_REQUIRE(engine.CommitSuite("exp", "suite", err));
    BOOST_CHECK(!engine.Report("exp", "cand", "author", "eval", "da", "de", false, false, false, err));
    BOOST_CHECK_EQUAL(err, "CANDIDATE");
    BOOST_REQUIRE(engine.BindCandidate("exp", "cand", err));
    BOOST_REQUIRE(engine.OpenExperiment("other", err));
    BOOST_REQUIRE(engine.BindCandidate("other", "else", err));
    BOOST_REQUIRE(engine.CommitSuite("other", "suite-b", err));
    BOOST_CHECK(!engine.Report("other", "cand", "author", "eval", "da", "de", false, false, false, err));
    BOOST_CHECK_EQUAL(err, "CANDIDATE");
    BOOST_CHECK_EQUAL(engine.report_count("cand"), std::size_t{0});
}

BOOST_AUTO_TEST_CASE(self_and_same_domain_are_not_accepting)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    BOOST_REQUIRE(OpenBound(engine, "exp", "cand"));
    BOOST_CHECK(!engine.Report("exp", "cand", "same", "same", "da", "de", false, true, true, err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK_EQUAL(engine.report_count("cand"), std::size_t{0});
    BOOST_CHECK_EQUAL(engine.regression_count("cand"), std::size_t{0});
    BOOST_CHECK(!engine.Report("exp", "cand", "author", "eval", "lab", "lab", true, true, true, err));
    BOOST_CHECK_EQUAL(err, "NOT_QUORUM");
    BOOST_CHECK_EQUAL(engine.report_count("cand"), std::size_t{0});
    BOOST_CHECK_EQUAL(engine.regression_count("cand"), std::size_t{0});
    BOOST_CHECK(!engine.qualified("cand"));
}

BOOST_AUTO_TEST_CASE(report_count_alone_does_not_qualify)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    BOOST_REQUIRE(OpenBound(engine, "exp", "cand"));
    BOOST_REQUIRE(Accepting(engine, "exp", "cand", "author-a", "eval-a", "da", "lab", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(engine.report_count("cand"), std::size_t{1});
    BOOST_CHECK(!engine.qualified("cand"));
    BOOST_REQUIRE(Accepting(engine, "exp", "cand", "author-b", "eval-a", "db", "other", err));
    BOOST_CHECK_EQUAL(engine.report_count("cand"), std::size_t{2});
    BOOST_CHECK(!engine.qualified("cand"));
    BOOST_CHECK(!engine.Promote("cand", err));
    BOOST_CHECK_EQUAL(err, "NOT_GRADUATED");
}

BOOST_AUTO_TEST_CASE(same_evaluator_domain_does_not_qualify)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err;
    BOOST_REQUIRE(OpenBound(engine, "exp", "cand"));
    BOOST_REQUIRE(Accepting(engine, "exp", "cand", "author-a", "eval-a", "da", "lab", err));
    BOOST_REQUIRE(Accepting(engine, "exp", "cand", "author-b", "eval-b", "db", "lab", err));
    BOOST_CHECK_EQUAL(engine.report_count("cand"), std::size_t{2});
    BOOST_CHECK(!engine.qualified("cand"));
}

BOOST_AUTO_TEST_CASE(two_distinct_evaluators_and_domains_qualify)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err;
    BOOST_REQUIRE(OpenBound(engine, "exp", "cand"));
    BOOST_REQUIRE(Accepting(engine, "exp", "cand", "author-a", "eval-a", "da", "lab-a", err));
    BOOST_CHECK(!engine.qualified("cand"));
    BOOST_REQUIRE(Accepting(engine, "exp", "cand", "author-b", "eval-b", "db", "lab-b", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(engine.report_count("cand"), std::size_t{2});
    BOOST_CHECK(engine.qualified("cand"));
    BOOST_REQUIRE(Accepting(engine, "exp", "cand", "author-c", "eval-c", "dc", "lab-c", err));
    BOOST_CHECK(engine.qualified("cand"));
    BOOST_REQUIRE(Accepting(engine, "exp", "cand", "author-a", "eval-a", "da", "lab-a", err));
    BOOST_CHECK_EQUAL(engine.report_count("cand"), std::size_t{4});
    BOOST_CHECK(engine.qualified("cand"));
}

BOOST_AUTO_TEST_CASE(reports_from_two_experiments_qualify_one_candidate)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err;
    BOOST_REQUIRE(engine.OpenExperiment("exp-a", err));
    BOOST_REQUIRE(engine.OpenExperiment("exp-b", err));
    BOOST_REQUIRE(engine.BindCandidate("exp-a", "cand", err));
    BOOST_REQUIRE(engine.BindCandidate("exp-b", "cand", err));
    BOOST_REQUIRE(engine.CommitSuite("exp-a", "suite-a", err));
    BOOST_REQUIRE(engine.CommitSuite("exp-b", "suite-b", err));
    BOOST_REQUIRE(Accepting(engine, "exp-a", "cand", "author-a", "eval-a", "da", "lab-a", err));
    BOOST_CHECK(!engine.qualified("cand"));
    BOOST_REQUIRE(Accepting(engine, "exp-b", "cand", "author-b", "eval-b", "db", "lab-b", err));
    BOOST_CHECK_EQUAL(engine.report_count("cand"), std::size_t{2});
    BOOST_CHECK(engine.qualified("cand"));
}

BOOST_AUTO_TEST_SUITE_END()
