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

void Prepare(modelnet::SwarmEvaluationEngine& engine, const std::string& candidate)
{
    std::string err;
    BOOST_REQUIRE(engine.OpenExperiment("exp", err));
    BOOST_REQUIRE(engine.BindCandidate("exp", candidate, err));
    BOOST_REQUIRE(engine.CommitSuite("exp", "suite", err));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_evalengine_promote_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unqualified_candidate_is_not_graduated)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    BOOST_CHECK(!engine.Promote("cand", err));
    BOOST_CHECK_EQUAL(err, "NOT_GRADUATED");
    BOOST_CHECK(!engine.promoted("cand"));
    Prepare(engine, "cand");
    BOOST_REQUIRE(engine.Report("exp", "cand", "author-a", "eval-a", "da", "lab-a", false, false, false, err));
    BOOST_CHECK(!engine.Promote("cand", err));
    BOOST_CHECK_EQUAL(err, "NOT_GRADUATED");
    BOOST_CHECK(!engine.promoted("cand"));
    BOOST_CHECK(!engine.realm_promoted());
    BOOST_CHECK(!engine.exact_replay_admitted());
    BOOST_CHECK(!engine.money());
}

BOOST_AUTO_TEST_CASE(clean_candidate_promotes_without_money_or_realm)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    Prepare(engine, "cand");
    BOOST_REQUIRE(engine.Report("exp", "cand", "author-a", "eval-a", "da", "lab-a", false, false, false, err));
    BOOST_REQUIRE(engine.Report("exp", "cand", "author-b", "eval-b", "db", "lab-b", false, false, false, err));
    BOOST_CHECK(engine.qualified("cand"));
    BOOST_REQUIRE(engine.Promote("cand", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(engine.promoted("cand"));
    BOOST_CHECK(!engine.Promote("cand", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(engine.promoted("cand"));
    BOOST_CHECK(!engine.realm_promoted());
    BOOST_CHECK(!engine.exact_replay_admitted());
    BOOST_CHECK(!engine.money());
    BOOST_CHECK(!engine.launched());
    BOOST_CHECK(!engine.gpu());
    BOOST_CHECK(!engine.broadcast());
    BOOST_CHECK_EQUAL(engine.bytes_moved(), std::uint64_t{0});
    BOOST_CHECK_EQUAL(engine.atoms_moved(), std::uint64_t{0});
    BOOST_CHECK_EQUAL(engine.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(regression_blocks_promotion_even_after_qualification)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    Prepare(engine, "cand");
    BOOST_REQUIRE(engine.Report("exp", "cand", "author-a", "eval-a", "da", "lab-a", false, false, false, err));
    BOOST_REQUIRE(engine.Report("exp", "cand", "author-b", "eval-b", "db", "lab-b", false, false, false, err));
    BOOST_CHECK(engine.qualified("cand"));
    BOOST_CHECK(!engine.Report("exp", "cand", "author-s", "eval-s", "ds", "lab-s", false, true, false, err));
    BOOST_CHECK_EQUAL(err, "SAFETY");
    BOOST_CHECK(!engine.qualified("cand"));
    BOOST_CHECK(!engine.Promote("cand", err));
    BOOST_CHECK_EQUAL(err, "REGRESSION");
    BOOST_CHECK(!engine.promoted("cand"));
    BOOST_CHECK_EQUAL(engine.regression_count("cand"), std::size_t{1});
    BOOST_CHECK_EQUAL(engine.report_count("cand"), std::size_t{2});
}

BOOST_AUTO_TEST_SUITE_END()
