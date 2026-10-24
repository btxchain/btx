// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnovalidated2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnovalidated2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_challenge_id_is_challenge)
{
    std::string err = "prior";
    modelnet::SwarmNotNoValidated2 note;
    note.unvalidated = true;
    note.want_move = true;
    const modelnet::SwarmNotNoValidated2Result result = modelnet::SwarmNoteNotNoValidated2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "CHALLENGE");
    BOOST_CHECK_EQUAL(err, "CHALLENGE");
}

BOOST_AUTO_TEST_CASE(unvalidated_without_want_move_is_not_moved)
{
    std::string err = "prior";
    modelnet::SwarmNotNoValidated2 note;
    note.challenge_id = "challenge-1";
    note.unvalidated = true;
    note.want_move = false;
    const modelnet::SwarmNotNoValidated2Result result = modelnet::SwarmNoteNotNoValidated2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_MOVED");
    BOOST_CHECK_EQUAL(err, "NOT_MOVED");
}

BOOST_AUTO_TEST_CASE(want_move_when_validated_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoValidated2 note;
    note.challenge_id = "challenge-1";
    note.unvalidated = false;
    note.want_move = true;
    const modelnet::SwarmNotNoValidated2Result result = modelnet::SwarmNoteNotNoValidated2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoValidated2 note;
    note.challenge_id = "challenge-1";
    note.unvalidated = false;
    note.want_move = false;
    const modelnet::SwarmNotNoValidated2Result result = modelnet::SwarmNoteNotNoValidated2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
