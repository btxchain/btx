// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoproposer.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoproposer_tests, BasicTestingSetup)

static modelnet::SwarmNotNoProposer NotedNote()
{
    modelnet::SwarmNotNoProposer note;
    note.proposal_id = "proposal-1";
    note.same_proposer = false;
    note.want_sign = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_proposal_id_is_proposal)
{
    modelnet::SwarmNotNoProposer note = NotedNote();
    note.proposal_id.clear();
    note.same_proposer = true;
    note.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoProposerResult result = modelnet::SwarmNoteNotNoProposer(note, err);
    BOOST_CHECK(!result.signed_proposal);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "PROPOSAL");
    BOOST_CHECK_EQUAL(err, "PROPOSAL");
    BOOST_CHECK(note.proposal_id.empty());
}

BOOST_AUTO_TEST_CASE(same_proposer_without_want_sign_is_same_signer)
{
    modelnet::SwarmNotNoProposer note = NotedNote();
    note.same_proposer = true;
    note.want_sign = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoProposerResult result = modelnet::SwarmNoteNotNoProposer(note, err);
    BOOST_CHECK(!result.signed_proposal);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "SAME_SIGNER");
    BOOST_CHECK_EQUAL(err, "SAME_SIGNER");
    BOOST_CHECK_EQUAL(note.proposal_id, "proposal-1");
}

BOOST_AUTO_TEST_CASE(want_sign_different_proposer_is_not_accepted)
{
    modelnet::SwarmNotNoProposer note = NotedNote();
    note.same_proposer = false;
    note.want_sign = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoProposerResult result = modelnet::SwarmNoteNotNoProposer(note, err);
    BOOST_CHECK(!result.signed_proposal);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "NOT_ACCEPTED");
    BOOST_CHECK_EQUAL(err, "NOT_ACCEPTED");
    BOOST_CHECK_EQUAL(note.proposal_id, "proposal-1");
}

BOOST_AUTO_TEST_CASE(plain_different_proposer_is_noted)
{
    modelnet::SwarmNotNoProposer note = NotedNote();
    note.same_proposer = false;
    note.want_sign = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoProposerResult result = modelnet::SwarmNoteNotNoProposer(note, err);
    BOOST_CHECK(!result.signed_proposal);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(note.proposal_id, "proposal-1");
}

BOOST_AUTO_TEST_SUITE_END()
