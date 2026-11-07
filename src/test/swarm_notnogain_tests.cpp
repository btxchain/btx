// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnogain.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnogain_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_step_id_is_step)
{
    modelnet::SwarmNotNoGain note;
    note.want_claim = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoGainResult result = modelnet::SwarmNoteNotNoGain(note, err);
    BOOST_CHECK(!result.gained);
    BOOST_CHECK(!result.evaluated);
    BOOST_CHECK_EQUAL(result.code, "STEP");
    BOOST_CHECK_EQUAL(err, "STEP");
}

BOOST_AUTO_TEST_CASE(want_claim_is_not_evaluated)
{
    modelnet::SwarmNotNoGain note;
    note.step_id = "step-1";
    note.want_claim = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoGainResult result = modelnet::SwarmNoteNotNoGain(note, err);
    BOOST_CHECK(!result.gained);
    BOOST_CHECK(!result.evaluated);
    BOOST_CHECK_EQUAL(result.code, "NOT_EVALUATED");
    BOOST_CHECK_EQUAL(err, "NOT_EVALUATED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoGain note;
    note.step_id = "step-1";
    note.want_claim = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoGainResult result = modelnet::SwarmNoteNotNoGain(note, err);
    BOOST_CHECK(!result.gained);
    BOOST_CHECK(!result.evaluated);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
