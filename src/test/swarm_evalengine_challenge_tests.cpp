// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalengine/engine.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_evalengine_challenge_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_or_unusable_challenge_stores_nothing)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    BOOST_CHECK(!engine.SubmitChallenge("", true, true, err));
    BOOST_CHECK_EQUAL(err, "CHALLENGE");
    BOOST_CHECK(!engine.SubmitChallenge("", false, false, err));
    BOOST_CHECK_EQUAL(err, "CHALLENGE");
    BOOST_CHECK(!engine.SubmitChallenge("chal", false, true, err));
    BOOST_CHECK_EQUAL(err, "NOT_CHALLENGE");
    BOOST_CHECK(!engine.SubmitChallenge("chal", true, false, err));
    BOOST_CHECK_EQUAL(err, "NOT_CHALLENGE");
    BOOST_CHECK(!engine.SubmitChallenge("chal", false, false, err));
    BOOST_CHECK_EQUAL(err, "NOT_CHALLENGE");
    BOOST_CHECK(!engine.challenge_validated("chal"));
    BOOST_CHECK(!engine.fitness_moves());
    BOOST_CHECK(!engine.fitness_moves("chal"));
    BOOST_CHECK(!engine.ValidateChallenge("chal", true, err));
    BOOST_CHECK_EQUAL(err, "CHALLENGE");
    BOOST_CHECK(!engine.fitness_moves());
}

BOOST_AUTO_TEST_CASE(stored_challenge_does_not_move_fitness)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    BOOST_REQUIRE(engine.SubmitChallenge("chal", true, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!engine.challenge_validated("chal"));
    BOOST_CHECK(!engine.fitness_moves());
    BOOST_CHECK(!engine.fitness_moves("chal"));
    BOOST_CHECK(!engine.SubmitChallenge("chal", true, true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!engine.fitness_moves());
}

BOOST_AUTO_TEST_CASE(independent_validation_moves_fitness_for_that_id)
{
    modelnet::SwarmEvaluationEngine engine;
    std::string err = "prior";
    BOOST_REQUIRE(engine.SubmitChallenge("chal", true, true, err));
    BOOST_REQUIRE(engine.SubmitChallenge("other", true, true, err));
    BOOST_CHECK(!engine.ValidateChallenge("missing", true, err));
    BOOST_CHECK_EQUAL(err, "CHALLENGE");
    BOOST_CHECK(!engine.ValidateChallenge("chal", false, err));
    BOOST_CHECK_EQUAL(err, "NOT_VALIDATED");
    BOOST_CHECK(!engine.challenge_validated("chal"));
    BOOST_CHECK(!engine.fitness_moves());
    BOOST_CHECK(!engine.fitness_moves("chal"));
    BOOST_REQUIRE(engine.ValidateChallenge("chal", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(engine.challenge_validated("chal"));
    BOOST_CHECK(engine.fitness_moves("chal"));
    BOOST_CHECK(engine.fitness_moves());
    BOOST_CHECK(!engine.challenge_validated("other"));
    BOOST_CHECK(!engine.fitness_moves("other"));
    BOOST_CHECK(!engine.ValidateChallenge("chal", true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(engine.challenge_validated("chal"));
    BOOST_CHECK(engine.fitness_moves());
    BOOST_CHECK(!engine.ValidateChallenge("chal", false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!engine.money());
    BOOST_CHECK(!engine.launched());
    BOOST_CHECK(!engine.gpu());
}

BOOST_AUTO_TEST_SUITE_END()
