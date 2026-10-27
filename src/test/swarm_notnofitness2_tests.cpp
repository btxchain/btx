// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofitness2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnofitness2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoFitness2 NotedNote()
{
    modelnet::SwarmNotNoFitness2 note;
    note.challenge_id = "challenge-1";
    note.informative = true;
    note.solvable = true;
    note.validated = true;
    note.want_move = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_challenge_id)
{
    modelnet::SwarmNotNoFitness2 note = NotedNote();
    note.challenge_id.clear();
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFitness2Result result = modelnet::SwarmNoteNotNoFitness2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "CHALLENGE");
    BOOST_CHECK_EQUAL(err, "CHALLENGE");
}

BOOST_AUTO_TEST_CASE(missing_validated)
{
    modelnet::SwarmNotNoFitness2 note = NotedNote();
    note.informative = true;
    note.solvable = true;
    note.validated = false;
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFitness2Result result = modelnet::SwarmNoteNotNoFitness2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_MOVED");
    BOOST_CHECK_EQUAL(err, "NOT_MOVED");
}

BOOST_AUTO_TEST_CASE(want_move_with_all_three_true)
{
    modelnet::SwarmNotNoFitness2 note = NotedNote();
    note.informative = true;
    note.solvable = true;
    note.validated = true;
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFitness2Result result = modelnet::SwarmNoteNotNoFitness2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(all_three_true_want_move_false)
{
    modelnet::SwarmNotNoFitness2 note = NotedNote();
    note.informative = true;
    note.solvable = true;
    note.validated = true;
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFitness2Result result = modelnet::SwarmNoteNotNoFitness2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
