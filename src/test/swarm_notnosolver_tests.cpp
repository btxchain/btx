// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosolver.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnosolver_tests, BasicTestingSetup)

static modelnet::SwarmNotNoSolver NotedNote()
{
    modelnet::SwarmNotNoSolver note;
    note.challenge_id = "challenge-1";
    note.solvable = true;
    note.want_move = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_challenge_id)
{
    modelnet::SwarmNotNoSolver note = NotedNote();
    note.challenge_id.clear();
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSolverResult result = modelnet::SwarmNoteNotNoSolver(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.fitness, 0);
    BOOST_CHECK_EQUAL(result.code, "CHALLENGE");
    BOOST_CHECK_EQUAL(err, "CHALLENGE");
}

BOOST_AUTO_TEST_CASE(solvable_false_is_unsolved)
{
    modelnet::SwarmNotNoSolver note = NotedNote();
    note.solvable = false;
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSolverResult result = modelnet::SwarmNoteNotNoSolver(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.fitness, 0);
    BOOST_CHECK_EQUAL(result.code, "UNSOLVED");
    BOOST_CHECK_EQUAL(err, "UNSOLVED");
}

BOOST_AUTO_TEST_CASE(want_move_is_held)
{
    modelnet::SwarmNotNoSolver note = NotedNote();
    note.solvable = true;
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSolverResult result = modelnet::SwarmNoteNotNoSolver(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.fitness, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoSolver note = NotedNote();
    note.solvable = true;
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSolverResult result = modelnet::SwarmNoteNotNoSolver(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.fitness, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
