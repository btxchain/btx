// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocheck.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocheck_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_step_id_is_step)
{
    std::string err = "prior";
    modelnet::SwarmNotNoCheck note;
    note.saved = true;
    note.want_resume = true;
    const modelnet::SwarmNotNoCheckResult result = modelnet::SwarmNoteNotNoCheck(note, err);
    BOOST_CHECK_EQUAL(result.resumed, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "STEP");
    BOOST_CHECK_EQUAL(err, "STEP");
}

BOOST_AUTO_TEST_CASE(unsaved_is_no_checkpoint)
{
    std::string err = "prior";
    modelnet::SwarmNotNoCheck note;
    note.step_id = "step-1";
    note.saved = false;
    note.want_resume = false;
    const modelnet::SwarmNotNoCheckResult result = modelnet::SwarmNoteNotNoCheck(note, err);
    BOOST_CHECK_EQUAL(result.resumed, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "NO_CHECKPOINT");
    BOOST_CHECK_EQUAL(err, "NO_CHECKPOINT");
}

BOOST_AUTO_TEST_CASE(want_resume_with_saved_is_no_checkpoint)
{
    std::string err = "prior";
    modelnet::SwarmNotNoCheck note;
    note.step_id = "step-1";
    note.saved = true;
    note.want_resume = true;
    const modelnet::SwarmNotNoCheckResult result = modelnet::SwarmNoteNotNoCheck(note, err);
    BOOST_CHECK_EQUAL(result.resumed, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "NO_CHECKPOINT");
    BOOST_CHECK_EQUAL(err, "NO_CHECKPOINT");
}

BOOST_AUTO_TEST_CASE(plain_saved_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoCheck note;
    note.step_id = "step-1";
    note.saved = true;
    note.want_resume = false;
    const modelnet::SwarmNotNoCheckResult result = modelnet::SwarmNoteNotNoCheck(note, err);
    BOOST_CHECK_EQUAL(result.resumed, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
