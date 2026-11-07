// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notvote.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notvote_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_vote_id_is_vote)
{
    modelnet::SwarmNotVote note;
    note.want_graduate = true;
    std::string err = "prior";
    const modelnet::SwarmNotVoteResult result = modelnet::SwarmNoteNotVote(note, err);
    BOOST_CHECK_EQUAL(result.graduated, false);
    BOOST_CHECK_EQUAL(result.realm_promoted, false);
    BOOST_CHECK_EQUAL(result.code, "VOTE");
    BOOST_CHECK_EQUAL(err, "VOTE");
}

BOOST_AUTO_TEST_CASE(want_graduate_is_not_graduated)
{
    modelnet::SwarmNotVote note;
    note.vote_id = "vote-1";
    note.want_graduate = true;
    std::string err = "prior";
    const modelnet::SwarmNotVoteResult result = modelnet::SwarmNoteNotVote(note, err);
    BOOST_CHECK_EQUAL(result.graduated, false);
    BOOST_CHECK_EQUAL(result.realm_promoted, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_GRADUATED");
    BOOST_CHECK_EQUAL(err, "NOT_GRADUATED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotVote note;
    note.vote_id = "vote-1";
    note.want_graduate = false;
    std::string err = "prior";
    const modelnet::SwarmNotVoteResult result = modelnet::SwarmNoteNotVote(note, err);
    BOOST_CHECK_EQUAL(result.graduated, false);
    BOOST_CHECK_EQUAL(result.realm_promoted, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
