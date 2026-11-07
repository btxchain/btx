// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalengine/engine.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <string>

namespace {

void Qualify(modelnet::SwarmEvaluationEngine& engine, const std::string& experiment, const std::string& candidate)
{
    std::string err;
    BOOST_REQUIRE(engine.OpenExperiment(experiment, err));
    BOOST_REQUIRE(engine.BindCandidate(experiment, candidate, err));
    BOOST_REQUIRE(engine.CommitSuite(experiment, "suite", err));
    BOOST_REQUIRE(engine.Report(experiment, candidate, "author-a", "eval-a", "da", "lab-a", false, false, false, err));
    BOOST_REQUIRE(engine.Report(experiment, candidate, "author-b", "eval-b", "db", "lab-b", false, false, false, err));
    BOOST_REQUIRE(engine.Promote(candidate, err));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_evalengine_adopt_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bad_policy_and_unpromoted_candidate_do_not_stage)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    Qualify(engine, "exp", "clean");
    BOOST_CHECK(!engine.Stage("chan", "clean", "hold", err));
    BOOST_CHECK_EQUAL(err, "POLICY");
    BOOST_CHECK(engine.staged("chan").empty());
    BOOST_CHECK(engine.active("chan").empty());
    BOOST_CHECK(!engine.Stage("chan", "other", "follow", err));
    BOOST_CHECK_EQUAL(err, "NOT_GRADUATED");
    BOOST_CHECK(engine.staged("chan").empty());
    BOOST_CHECK(engine.active("chan").empty());
    BOOST_CHECK(!engine.Stage("chan", "other", "pin", err));
    BOOST_CHECK_EQUAL(err, "NOT_GRADUATED");
    BOOST_CHECK_EQUAL(engine.adoption_count("chan"), std::size_t{0});
}

BOOST_AUTO_TEST_CASE(pin_and_refuse_leave_both_heads_unchanged)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    Qualify(engine, "exp", "clean");
    BOOST_REQUIRE(engine.Stage("chan", "clean", "pin", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(engine.staged("chan").empty());
    BOOST_CHECK(engine.active("chan").empty());
    BOOST_REQUIRE(engine.Stage("chan", "clean", "refuse", err));
    BOOST_CHECK(engine.staged("chan").empty());
    BOOST_CHECK(engine.active("chan").empty());
    BOOST_CHECK(!engine.Adopt("chan", err));
    BOOST_CHECK_EQUAL(err, "NOT_STAGED");
    BOOST_REQUIRE(engine.Stage("chan", "clean", "follow", err));
    BOOST_CHECK_EQUAL(engine.staged("chan"), "clean");
    BOOST_CHECK(engine.active("chan").empty());
    BOOST_REQUIRE(engine.Stage("chan", "clean", "pin", err));
    BOOST_CHECK_EQUAL(engine.staged("chan"), "clean");
    BOOST_CHECK(engine.active("chan").empty());
    BOOST_REQUIRE(engine.Stage("chan", "clean", "refuse", err));
    BOOST_CHECK_EQUAL(engine.staged("chan"), "clean");
    BOOST_CHECK(engine.active("chan").empty());
    BOOST_CHECK(!engine.Stage("chan", "clean", "Follow", err));
    BOOST_CHECK_EQUAL(err, "POLICY");
    BOOST_CHECK_EQUAL(engine.staged("chan"), "clean");
}

BOOST_AUTO_TEST_CASE(follow_stages_and_adopt_moves_the_head)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    Qualify(engine, "exp", "clean");
    BOOST_REQUIRE(engine.BindCandidate("exp", "next", err));
    BOOST_REQUIRE(engine.Report("exp", "next", "author-c", "eval-c", "dc", "lab-c", false, false, false, err));
    BOOST_REQUIRE(engine.Report("exp", "next", "author-d", "eval-d", "dd", "lab-d", false, false, false, err));
    BOOST_REQUIRE(engine.Promote("next", err));

    BOOST_CHECK(!engine.Adopt("chan", err));
    BOOST_CHECK_EQUAL(err, "NOT_STAGED");
    BOOST_REQUIRE(engine.Stage("chan", "clean", "follow", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(engine.staged("chan"), "clean");
    BOOST_CHECK(engine.active("chan").empty());
    BOOST_REQUIRE(engine.Stage("chan", "next", "follow", err));
    BOOST_CHECK_EQUAL(engine.staged("chan"), "next");
    BOOST_CHECK(engine.active("chan").empty());
    BOOST_REQUIRE(engine.Adopt("chan", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(engine.active("chan"), "next");
    BOOST_CHECK(engine.staged("chan").empty());
    BOOST_CHECK_EQUAL(engine.adoption_count("chan"), std::size_t{1});
    BOOST_CHECK(!engine.Adopt("chan", err));
    BOOST_CHECK_EQUAL(err, "NOT_STAGED");
    BOOST_CHECK_EQUAL(engine.active("chan"), "next");

    BOOST_REQUIRE(engine.Stage("chan", "clean", "follow", err));
    BOOST_CHECK_EQUAL(engine.staged("chan"), "clean");
    BOOST_CHECK_EQUAL(engine.active("chan"), "next");
    BOOST_REQUIRE(engine.Adopt("chan", err));
    BOOST_CHECK_EQUAL(engine.active("chan"), "clean");
    BOOST_CHECK(engine.staged("chan").empty());
    BOOST_CHECK_EQUAL(engine.adoption_count("chan"), std::size_t{2});
    BOOST_CHECK_EQUAL(engine.adoption_count("other"), std::size_t{0});
    BOOST_CHECK(engine.active("other").empty());
}

BOOST_AUTO_TEST_CASE(one_plane_evaluates_promotes_and_adopts)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";

    BOOST_REQUIRE(engine.OpenExperiment("exp", err));
    BOOST_REQUIRE(engine.BindCandidate("exp", "clean", err));
    BOOST_REQUIRE(engine.BindCandidate("exp", "unsafe", err));
    BOOST_REQUIRE(engine.CommitSuite("exp", "suite", err));

    BOOST_REQUIRE(engine.Report("exp", "clean", "author-a", "eval-a", "da", "lab-a", false, false, false, err));
    BOOST_REQUIRE(engine.Report("exp", "clean", "author-b", "eval-b", "db", "lab-b", false, false, false, err));
    BOOST_CHECK(!engine.Report("exp", "clean", "eval-c", "eval-c", "dc", "lab-c", false, false, false, err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK(!engine.Report("exp", "clean", "author-d", "eval-d", "dd", "lab-d", true, false, false, err));
    BOOST_CHECK_EQUAL(err, "HOLDOUT");
    BOOST_CHECK_EQUAL(engine.report_count("clean"), std::size_t{2});
    BOOST_CHECK(engine.qualified("clean"));

    BOOST_REQUIRE(engine.Report("exp", "unsafe", "author-a", "eval-a", "da", "lab-a", false, false, false, err));
    BOOST_REQUIRE(engine.Report("exp", "unsafe", "author-b", "eval-b", "db", "lab-b", false, false, false, err));
    BOOST_CHECK(engine.qualified("unsafe"));
    BOOST_CHECK(!engine.Report("exp", "unsafe", "author-s", "eval-s", "ds", "lab-s", false, true, false, err));
    BOOST_CHECK_EQUAL(err, "SAFETY");
    BOOST_CHECK(!engine.qualified("unsafe"));
    BOOST_CHECK(!engine.Promote("unsafe", err));
    BOOST_CHECK_EQUAL(err, "REGRESSION");
    BOOST_CHECK(!engine.promoted("unsafe"));

    BOOST_REQUIRE(engine.SubmitChallenge("chal", true, true, err));
    BOOST_CHECK(!engine.fitness_moves());
    BOOST_CHECK(!engine.fitness_moves("chal"));
    BOOST_REQUIRE(engine.ValidateChallenge("chal", true, err));
    BOOST_CHECK(engine.challenge_validated("chal"));
    BOOST_CHECK(engine.fitness_moves());
    BOOST_CHECK(engine.fitness_moves("chal"));

    BOOST_REQUIRE(engine.Promote("clean", err));
    BOOST_CHECK(engine.promoted("clean"));
    BOOST_CHECK(!engine.realm_promoted());
    BOOST_CHECK(!engine.exact_replay_admitted());
    BOOST_CHECK(!engine.money());
    BOOST_CHECK_EQUAL(engine.regression_count("unsafe"), std::size_t{1});

    BOOST_CHECK(engine.active("chan").empty());
    BOOST_REQUIRE(engine.Stage("chan", "clean", "follow", err));
    BOOST_CHECK_EQUAL(engine.staged("chan"), "clean");
    BOOST_CHECK(engine.active("chan").empty());
    BOOST_REQUIRE(engine.Adopt("chan", err));
    BOOST_CHECK_EQUAL(engine.active("chan"), "clean");
    BOOST_CHECK(engine.staged("chan").empty());
    BOOST_CHECK_EQUAL(engine.adoption_count("chan"), std::size_t{1});

    BOOST_CHECK_EQUAL(engine.regression_count("unsafe"), std::size_t{1});
    BOOST_CHECK(!engine.qualified("unsafe"));
    BOOST_CHECK(engine.qualified("clean"));
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
