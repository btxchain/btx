// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnochallinfo2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnochallinfo2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_challenge_id)
{
    modelnet::SwarmNotNoChallInfo2 note;
    note.challenge_id.clear();
    note.uninformative = false;
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoChallInfo2Result result = modelnet::SwarmNoteNotNoChallInfo2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "CHALLENGE");
    BOOST_CHECK_EQUAL(err, "CHALLENGE");
}

BOOST_AUTO_TEST_CASE(uninformative_want_move_false)
{
    modelnet::SwarmNotNoChallInfo2 note;
    note.challenge_id = "challenge-1";
    note.uninformative = true;
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoChallInfo2Result result = modelnet::SwarmNoteNotNoChallInfo2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_MOVED");
    BOOST_CHECK_EQUAL(err, "NOT_MOVED");
}

BOOST_AUTO_TEST_CASE(want_move_uninformative_false)
{
    modelnet::SwarmNotNoChallInfo2 note;
    note.challenge_id = "challenge-1";
    note.uninformative = false;
    note.want_move = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoChallInfo2Result result = modelnet::SwarmNoteNotNoChallInfo2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted_neither)
{
    modelnet::SwarmNotNoChallInfo2 note;
    note.challenge_id = "challenge-1";
    note.uninformative = false;
    note.want_move = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoChallInfo2Result result = modelnet::SwarmNoteNotNoChallInfo2(note, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
