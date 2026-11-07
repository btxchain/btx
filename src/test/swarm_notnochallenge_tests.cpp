// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnochallenge.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnochallenge_tests, BasicTestingSetup)

static modelnet::SwarmNotNoChallenge NotedNote()
{
    modelnet::SwarmNotNoChallenge note;
    note.challenge_id = "challenge-1";
    note.informative = true;
    note.solvable = true;
    note.validated = true;
    note.want_move = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_challenge_id)
{
    modelnet::SwarmNotNoChallenge note = NotedNote();
    note.challenge_id.clear();
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoChallengeResult result = modelnet::SwarmNoteNotNoChallenge(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.fitness_changed);
    BOOST_CHECK_EQUAL(result.code, "CHALLENGE");
    BOOST_CHECK_EQUAL(err, "CHALLENGE");
}

BOOST_AUTO_TEST_CASE(missing_one_flag_is_held)
{
    modelnet::SwarmNotNoChallenge note = NotedNote();
    note.informative = false;
    note.solvable = true;
    note.validated = true;
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoChallengeResult result = modelnet::SwarmNoteNotNoChallenge(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.fitness_changed);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_move_with_all_three_true)
{
    modelnet::SwarmNotNoChallenge note = NotedNote();
    note.informative = true;
    note.solvable = true;
    note.validated = true;
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoChallengeResult result = modelnet::SwarmNoteNotNoChallenge(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.fitness_changed);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(quiet_note_all_three_true)
{
    modelnet::SwarmNotNoChallenge note = NotedNote();
    note.informative = true;
    note.solvable = true;
    note.validated = true;
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoChallengeResult result = modelnet::SwarmNoteNotNoChallenge(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK(!result.fitness_changed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
