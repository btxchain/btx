// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_assurance.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_assurance_tests, BasicTestingSetup)

static modelnet::SwarmAssurance NotedChannel()
{
    modelnet::SwarmAssurance note;
    note.channel_id = "chan-a";
    note.want_work_proof = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_channel_id_is_assurance)
{
    modelnet::SwarmAssurance note = NotedChannel();
    note.channel_id.clear();
    std::string err = "prior";
    const modelnet::SwarmAssuranceResult result = modelnet::SwarmNoteAssurance(note, err);
    BOOST_CHECK(!result.work_proof);
    BOOST_CHECK(result.assurance.empty());
    BOOST_CHECK_EQUAL(result.code, "ASSURANCE");
    BOOST_CHECK_EQUAL(err, "ASSURANCE");
}

BOOST_AUTO_TEST_CASE(empty_channel_id_wins_over_want_work_proof)
{
    modelnet::SwarmAssurance note = NotedChannel();
    note.channel_id.clear();
    note.want_work_proof = true;
    std::string err = "prior";
    const modelnet::SwarmAssuranceResult result = modelnet::SwarmNoteAssurance(note, err);
    BOOST_CHECK(!result.work_proof);
    BOOST_CHECK(result.assurance.empty());
    BOOST_CHECK_EQUAL(result.code, "ASSURANCE");
    BOOST_CHECK_EQUAL(err, "ASSURANCE");
}

BOOST_AUTO_TEST_CASE(want_work_proof_is_not_work_proof)
{
    modelnet::SwarmAssurance note = NotedChannel();
    note.want_work_proof = true;
    std::string err = "prior";
    const modelnet::SwarmAssuranceResult result = modelnet::SwarmNoteAssurance(note, err);
    BOOST_CHECK(!result.work_proof);
    BOOST_CHECK_EQUAL(result.assurance, "CUMULATIVE_NOT_WORK_PROOF");
    BOOST_CHECK_EQUAL(result.code, "NOT_WORK_PROOF");
    BOOST_CHECK_EQUAL(err, "NOT_WORK_PROOF");
}

BOOST_AUTO_TEST_CASE(noted_channel_is_not_work_proof)
{
    modelnet::SwarmAssurance note = NotedChannel();
    std::string err = "prior";
    const modelnet::SwarmAssuranceResult result = modelnet::SwarmNoteAssurance(note, err);
    BOOST_CHECK(!result.work_proof);
    BOOST_CHECK_EQUAL(result.assurance, "CUMULATIVE_NOT_WORK_PROOF");
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
