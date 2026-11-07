// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosolvable2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnosolvable2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_challenge_id_is_challenge)
{
    modelnet::SwarmNotNoSolvable2 note;
    note.challenge_id.clear();
    note.unsolved = false;
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSolvable2Result result = modelnet::SwarmNoteNotNoSolvable2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "CHALLENGE");
    BOOST_CHECK_EQUAL(err, "CHALLENGE");
}

BOOST_AUTO_TEST_CASE(unsolved_true_is_not_moved)
{
    modelnet::SwarmNotNoSolvable2 note;
    note.challenge_id = "challenge-1";
    note.unsolved = true;
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSolvable2Result result = modelnet::SwarmNoteNotNoSolvable2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_MOVED");
    BOOST_CHECK_EQUAL(err, "NOT_MOVED");
}

BOOST_AUTO_TEST_CASE(want_move_true_is_held)
{
    modelnet::SwarmNotNoSolvable2 note;
    note.challenge_id = "challenge-1";
    note.unsolved = false;
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSolvable2Result result = modelnet::SwarmNoteNotNoSolvable2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(neither_is_noted)
{
    modelnet::SwarmNotNoSolvable2 note;
    note.challenge_id = "challenge-1";
    note.unsolved = false;
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSolvable2Result result = modelnet::SwarmNoteNotNoSolvable2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
