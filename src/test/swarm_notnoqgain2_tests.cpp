// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoqgain2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoqgain2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_step_id_is_step)
{
    std::string err = "prior";
    modelnet::SwarmNotNoQgain2 note;
    note.one_step = true;
    note.want_claim = true;
    const modelnet::SwarmNotNoQgain2Result result = modelnet::SwarmNoteNotNoQgain2(note, err);
    BOOST_CHECK(!result.gained);
    BOOST_CHECK_EQUAL(result.code, "STEP");
    BOOST_CHECK_EQUAL(err, "STEP");
}

BOOST_AUTO_TEST_CASE(one_step_without_want_claim_is_not_gain)
{
    std::string err = "prior";
    modelnet::SwarmNotNoQgain2 note;
    note.step_id = "step-a";
    note.one_step = true;
    note.want_claim = false;
    const modelnet::SwarmNotNoQgain2Result result = modelnet::SwarmNoteNotNoQgain2(note, err);
    BOOST_CHECK(!result.gained);
    BOOST_CHECK_EQUAL(result.code, "NOT_GAIN");
    BOOST_CHECK_EQUAL(err, "NOT_GAIN");
}

BOOST_AUTO_TEST_CASE(want_claim_without_one_step_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoQgain2 note;
    note.step_id = "step-a";
    note.one_step = false;
    note.want_claim = true;
    const modelnet::SwarmNotNoQgain2Result result = modelnet::SwarmNoteNotNoQgain2(note, err);
    BOOST_CHECK(!result.gained);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_without_one_step_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoQgain2 note;
    note.step_id = "step-a";
    note.one_step = false;
    note.want_claim = false;
    const modelnet::SwarmNotNoQgain2Result result = modelnet::SwarmNoteNotNoQgain2(note, err);
    BOOST_CHECK(!result.gained);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
