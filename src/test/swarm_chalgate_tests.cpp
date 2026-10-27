// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_chalgate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_chalgate_tests, BasicTestingSetup)

static modelnet::SwarmChallengeGate NotedGate()
{
    modelnet::SwarmChallengeGate gate;
    gate.challenge_id = "challenge-a";
    gate.informative = true;
    gate.solvable = true;
    gate.independently_validated = true;
    gate.want_fitness = false;
    return gate;
}

BOOST_AUTO_TEST_CASE(empty_challenge_id_is_challenge)
{
    modelnet::SwarmChallengeGate gate = NotedGate();
    gate.challenge_id.clear();
    std::string err = "prior";
    const modelnet::SwarmChallengeGateResult result = modelnet::SwarmNoteChallengeGate(gate, err);
    BOOST_CHECK(!result.fitness_moved);
    BOOST_CHECK_EQUAL(result.code, "CHALLENGE");
    BOOST_CHECK_EQUAL(err, "CHALLENGE");
}

BOOST_AUTO_TEST_CASE(empty_challenge_id_wins_over_unready_and_want_fitness)
{
    modelnet::SwarmChallengeGate gate = NotedGate();
    gate.challenge_id.clear();
    gate.informative = false;
    gate.solvable = false;
    gate.independently_validated = false;
    gate.want_fitness = true;
    std::string err = "prior";
    const modelnet::SwarmChallengeGateResult result = modelnet::SwarmNoteChallengeGate(gate, err);
    BOOST_CHECK(!result.fitness_moved);
    BOOST_CHECK_EQUAL(result.code, "CHALLENGE");
    BOOST_CHECK_EQUAL(err, "CHALLENGE");
}

BOOST_AUTO_TEST_CASE(unvalidated_want_fitness_is_unready)
{
    modelnet::SwarmChallengeGate gate = NotedGate();
    gate.independently_validated = false;
    gate.want_fitness = true;
    std::string err = "prior";
    const modelnet::SwarmChallengeGateResult result = modelnet::SwarmNoteChallengeGate(gate, err);
    BOOST_CHECK(!result.fitness_moved);
    BOOST_CHECK_EQUAL(result.code, "UNREADY");
    BOOST_CHECK_EQUAL(err, "UNREADY");
}

BOOST_AUTO_TEST_CASE(not_informative_is_unready)
{
    modelnet::SwarmChallengeGate gate = NotedGate();
    gate.informative = false;
    gate.want_fitness = true;
    std::string err = "prior";
    const modelnet::SwarmChallengeGateResult result = modelnet::SwarmNoteChallengeGate(gate, err);
    BOOST_CHECK(!result.fitness_moved);
    BOOST_CHECK_EQUAL(result.code, "UNREADY");
    BOOST_CHECK_EQUAL(err, "UNREADY");
}

BOOST_AUTO_TEST_CASE(not_solvable_is_unready)
{
    modelnet::SwarmChallengeGate gate = NotedGate();
    gate.solvable = false;
    gate.want_fitness = true;
    std::string err = "prior";
    const modelnet::SwarmChallengeGateResult result = modelnet::SwarmNoteChallengeGate(gate, err);
    BOOST_CHECK(!result.fitness_moved);
    BOOST_CHECK_EQUAL(result.code, "UNREADY");
    BOOST_CHECK_EQUAL(err, "UNREADY");
}

BOOST_AUTO_TEST_CASE(want_fitness_is_held_and_does_not_move_fitness)
{
    modelnet::SwarmChallengeGate gate = NotedGate();
    gate.want_fitness = true;
    std::string err = "prior";
    const modelnet::SwarmChallengeGateResult result = modelnet::SwarmNoteChallengeGate(gate, err);
    BOOST_CHECK(!result.fitness_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(ready_challenge_is_noted_and_does_not_move_fitness)
{
    modelnet::SwarmChallengeGate gate = NotedGate();
    std::string err = "prior";
    const modelnet::SwarmChallengeGateResult result = modelnet::SwarmNoteChallengeGate(gate, err);
    BOOST_CHECK(!result.fitness_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
