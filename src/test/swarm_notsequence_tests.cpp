// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notsequence.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notsequence_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    std::string err = "prior";
    modelnet::SwarmNotSequence note;
    note.step_count = 2;
    note.want_step = true;
    const modelnet::SwarmNotSequenceResult result = modelnet::SwarmNoteNotSequence(note, err);
    BOOST_CHECK(!result.stepped);
    BOOST_CHECK_EQUAL(result.applied_steps, 0);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(step_count_zero_is_one_step_even_when_want_step_is_false)
{
    std::string err = "prior";
    modelnet::SwarmNotSequence note;
    note.channel_id = "channel-1";
    note.step_count = 0;
    note.want_step = false;
    const modelnet::SwarmNotSequenceResult result = modelnet::SwarmNoteNotSequence(note, err);
    BOOST_CHECK(!result.stepped);
    BOOST_CHECK_EQUAL(result.applied_steps, 0);
    BOOST_CHECK_EQUAL(result.code, "ONE_STEP");
    BOOST_CHECK_EQUAL(err, "ONE_STEP");
}

BOOST_AUTO_TEST_CASE(step_count_two_is_one_step)
{
    std::string err = "prior";
    modelnet::SwarmNotSequence note;
    note.channel_id = "channel-1";
    note.step_count = 2;
    note.want_step = false;
    const modelnet::SwarmNotSequenceResult result = modelnet::SwarmNoteNotSequence(note, err);
    BOOST_CHECK(!result.stepped);
    BOOST_CHECK_EQUAL(result.applied_steps, 0);
    BOOST_CHECK_EQUAL(result.code, "ONE_STEP");
    BOOST_CHECK_EQUAL(err, "ONE_STEP");
}

BOOST_AUTO_TEST_CASE(step_count_one_with_want_step_is_one_step)
{
    std::string err = "prior";
    modelnet::SwarmNotSequence note;
    note.channel_id = "channel-1";
    note.step_count = 1;
    note.want_step = true;
    const modelnet::SwarmNotSequenceResult result = modelnet::SwarmNoteNotSequence(note, err);
    BOOST_CHECK(!result.stepped);
    BOOST_CHECK_EQUAL(result.applied_steps, 0);
    BOOST_CHECK_EQUAL(result.code, "ONE_STEP");
    BOOST_CHECK_EQUAL(err, "ONE_STEP");
}

BOOST_AUTO_TEST_CASE(plain_step_count_one_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotSequence note;
    note.channel_id = "channel-1";
    note.step_count = 1;
    note.want_step = false;
    const modelnet::SwarmNotSequenceResult result = modelnet::SwarmNoteNotSequence(note, err);
    BOOST_CHECK(!result.stepped);
    BOOST_CHECK_EQUAL(result.applied_steps, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
