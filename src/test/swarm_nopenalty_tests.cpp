// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nopenalty.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_nopenalty_tests, BasicTestingSetup)

static modelnet::SwarmPenaltyNote NotedNote()
{
    modelnet::SwarmPenaltyNote note;
    note.channel_id = "ch-1";
    note.stale_state = false;
    note.want_secp_penalty = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_channel_id_is_penalty)
{
    modelnet::SwarmPenaltyNote note = NotedNote();
    note.channel_id.clear();
    std::string err = "prior";
    const modelnet::SwarmPenaltyResult result = modelnet::SwarmNotePenalty(note, err);
    BOOST_CHECK(!result.secp_penalty);
    BOOST_CHECK_EQUAL(result.code, "PENALTY");
    BOOST_CHECK_EQUAL(err, "PENALTY");
}

BOOST_AUTO_TEST_CASE(empty_channel_id_wins_over_want_secp_and_stale)
{
    modelnet::SwarmPenaltyNote note = NotedNote();
    note.channel_id.clear();
    note.stale_state = true;
    note.want_secp_penalty = true;
    std::string err = "prior";
    const modelnet::SwarmPenaltyResult result = modelnet::SwarmNotePenalty(note, err);
    BOOST_CHECK(!result.secp_penalty);
    BOOST_CHECK_EQUAL(result.code, "PENALTY");
    BOOST_CHECK_EQUAL(err, "PENALTY");
}

BOOST_AUTO_TEST_CASE(want_secp_penalty_is_no_penalty)
{
    modelnet::SwarmPenaltyNote note = NotedNote();
    note.want_secp_penalty = true;
    std::string err = "prior";
    const modelnet::SwarmPenaltyResult result = modelnet::SwarmNotePenalty(note, err);
    BOOST_CHECK(!result.secp_penalty);
    BOOST_CHECK_EQUAL(result.code, "NO_PENALTY");
    BOOST_CHECK_EQUAL(err, "NO_PENALTY");
}

BOOST_AUTO_TEST_CASE(want_secp_penalty_wins_over_stale_state)
{
    modelnet::SwarmPenaltyNote note = NotedNote();
    note.stale_state = true;
    note.want_secp_penalty = true;
    std::string err = "prior";
    const modelnet::SwarmPenaltyResult result = modelnet::SwarmNotePenalty(note, err);
    BOOST_CHECK(!result.secp_penalty);
    BOOST_CHECK_EQUAL(result.code, "NO_PENALTY");
    BOOST_CHECK_EQUAL(err, "NO_PENALTY");
}

BOOST_AUTO_TEST_CASE(stale_state_is_hashlock)
{
    modelnet::SwarmPenaltyNote note = NotedNote();
    note.stale_state = true;
    std::string err = "prior";
    const modelnet::SwarmPenaltyResult result = modelnet::SwarmNotePenalty(note, err);
    BOOST_CHECK(!result.secp_penalty);
    BOOST_CHECK_EQUAL(result.code, "HASHLOCK");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmPenaltyNote note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmPenaltyResult result = modelnet::SwarmNotePenalty(note, err);
    BOOST_CHECK(!result.secp_penalty);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
