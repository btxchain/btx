// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfitness.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notfitness_tests, BasicTestingSetup)

static modelnet::SwarmNotFitness NotedNote()
{
    modelnet::SwarmNotFitness note;
    note.challenge_id = "challenge-1";
    note.informative = true;
    note.solvable = true;
    note.validated = true;
    note.want_move = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_challenge_id)
{
    modelnet::SwarmNotFitness note = NotedNote();
    note.challenge_id.clear();
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotFitnessResult result = modelnet::SwarmNoteNotFitness(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.fitness, 0);
    BOOST_CHECK_EQUAL(result.code, "CHALLENGE");
    BOOST_CHECK_EQUAL(err, "CHALLENGE");
}

BOOST_AUTO_TEST_CASE(missing_validated)
{
    modelnet::SwarmNotFitness note = NotedNote();
    note.informative = true;
    note.solvable = true;
    note.validated = false;
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotFitnessResult result = modelnet::SwarmNoteNotFitness(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.fitness, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_move_with_all_three_true)
{
    modelnet::SwarmNotFitness note = NotedNote();
    note.informative = true;
    note.solvable = true;
    note.validated = true;
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotFitnessResult result = modelnet::SwarmNoteNotFitness(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.fitness, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_all_three_true)
{
    modelnet::SwarmNotFitness note = NotedNote();
    note.informative = true;
    note.solvable = true;
    note.validated = true;
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotFitnessResult result = modelnet::SwarmNoteNotFitness(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.fitness, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
