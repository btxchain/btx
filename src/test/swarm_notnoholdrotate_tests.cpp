// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoholdrotate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoholdrotate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_eval_id_is_eval)
{
    modelnet::SwarmNotNoHoldRotate note;
    note.eval_id.clear();
    note.fixed_holdout = true;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoHoldRotateResult result = modelnet::SwarmNoteNotNoHoldRotate(note, err);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "EVAL");
    BOOST_CHECK_EQUAL(err, "EVAL");
}

BOOST_AUTO_TEST_CASE(fixed_holdout_is_not_rotated)
{
    modelnet::SwarmNotNoHoldRotate note;
    note.eval_id = "eval-1";
    note.fixed_holdout = true;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoHoldRotateResult result = modelnet::SwarmNoteNotNoHoldRotate(note, err);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "NOT_ROTATED");
    BOOST_CHECK_EQUAL(err, "NOT_ROTATED");
}

BOOST_AUTO_TEST_CASE(want_train_is_not_run)
{
    modelnet::SwarmNotNoHoldRotate note;
    note.eval_id = "eval-1";
    note.fixed_holdout = false;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoHoldRotateResult result = modelnet::SwarmNoteNotNoHoldRotate(note, err);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "NOT_RUN");
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoHoldRotate note;
    note.eval_id = "eval-1";
    note.fixed_holdout = false;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoHoldRotateResult result = modelnet::SwarmNoteNotNoHoldRotate(note, err);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
