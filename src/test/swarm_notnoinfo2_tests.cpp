// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoinfo2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoinfo2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoInfo2 NotedNote()
{
    modelnet::SwarmNotNoInfo2 note;
    note.challenge_id = "challenge-1";
    note.informative = true;
    note.want_move = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_challenge_id)
{
    modelnet::SwarmNotNoInfo2 note = NotedNote();
    note.challenge_id.clear();
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoInfo2Result result = modelnet::SwarmNoteNotNoInfo2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.fitness, 0);
    BOOST_CHECK_EQUAL(result.code, "CHALLENGE");
    BOOST_CHECK_EQUAL(err, "CHALLENGE");
}

BOOST_AUTO_TEST_CASE(informative_false_is_not_informative)
{
    modelnet::SwarmNotNoInfo2 note = NotedNote();
    note.informative = false;
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoInfo2Result result = modelnet::SwarmNoteNotNoInfo2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.fitness, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_INFORMATIVE");
    BOOST_CHECK_EQUAL(err, "NOT_INFORMATIVE");
}

BOOST_AUTO_TEST_CASE(want_move_is_held)
{
    modelnet::SwarmNotNoInfo2 note = NotedNote();
    note.informative = true;
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoInfo2Result result = modelnet::SwarmNoteNotNoInfo2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.fitness, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoInfo2 note = NotedNote();
    note.informative = true;
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoInfo2Result result = modelnet::SwarmNoteNotNoInfo2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.fitness, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
