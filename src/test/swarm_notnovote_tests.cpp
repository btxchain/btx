// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnovote.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnovote_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_proposal_id_is_proposal)
{
    modelnet::SwarmNotNoVote note;
    note.vote_ppm = 510000;
    note.want_graduate = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoVoteResult result = modelnet::SwarmNoteNotNoVote(note, err);
    BOOST_CHECK_EQUAL(result.graduated, false);
    BOOST_CHECK_EQUAL(result.admitted, false);
    BOOST_CHECK_EQUAL(result.code, "PROPOSAL");
    BOOST_CHECK_EQUAL(err, "PROPOSAL");
}

BOOST_AUTO_TEST_CASE(vote_ppm_510000_is_not_graduated)
{
    modelnet::SwarmNotNoVote note;
    note.proposal_id = "proposal-1";
    note.vote_ppm = 510000;
    note.want_graduate = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoVoteResult result = modelnet::SwarmNoteNotNoVote(note, err);
    BOOST_CHECK_EQUAL(result.graduated, false);
    BOOST_CHECK_EQUAL(result.admitted, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_GRADUATED");
    BOOST_CHECK_EQUAL(err, "NOT_GRADUATED");
}

BOOST_AUTO_TEST_CASE(want_graduate_at_zero_is_not_graduated)
{
    modelnet::SwarmNotNoVote note;
    note.proposal_id = "proposal-1";
    note.vote_ppm = 0;
    note.want_graduate = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoVoteResult result = modelnet::SwarmNoteNotNoVote(note, err);
    BOOST_CHECK_EQUAL(result.graduated, false);
    BOOST_CHECK_EQUAL(result.admitted, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_GRADUATED");
    BOOST_CHECK_EQUAL(err, "NOT_GRADUATED");
}

BOOST_AUTO_TEST_CASE(plain_zero_is_noted)
{
    modelnet::SwarmNotNoVote note;
    note.proposal_id = "proposal-1";
    note.vote_ppm = 0;
    note.want_graduate = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoVoteResult result = modelnet::SwarmNoteNotNoVote(note, err);
    BOOST_CHECK_EQUAL(result.graduated, false);
    BOOST_CHECK_EQUAL(result.admitted, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
