// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnostep.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnostep_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_step_id_is_step)
{
    std::string err = "prior";
    modelnet::SwarmNotNoStep note;
    note.steps = 2;
    note.want_distributed = true;
    const modelnet::SwarmNotNoStepResult result = modelnet::SwarmNoteNotNoStep(note, err);
    BOOST_CHECK(!result.distributed);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "STEP");
    BOOST_CHECK_EQUAL(err, "STEP");
}

BOOST_AUTO_TEST_CASE(steps_of_1_is_not_distributed)
{
    std::string err = "prior";
    modelnet::SwarmNotNoStep note;
    note.step_id = "step-note";
    note.steps = 1;
    note.want_distributed = false;
    const modelnet::SwarmNotNoStepResult result = modelnet::SwarmNoteNotNoStep(note, err);
    BOOST_CHECK(!result.distributed);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "NOT_DISTRIBUTED");
    BOOST_CHECK_EQUAL(err, "NOT_DISTRIBUTED");
}

BOOST_AUTO_TEST_CASE(want_distributed_with_steps_greater_than_1_is_not_distributed)
{
    std::string err = "prior";
    modelnet::SwarmNotNoStep note;
    note.step_id = "step-note";
    note.steps = 2;
    note.want_distributed = true;
    const modelnet::SwarmNotNoStepResult result = modelnet::SwarmNoteNotNoStep(note, err);
    BOOST_CHECK(!result.distributed);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "NOT_DISTRIBUTED");
    BOOST_CHECK_EQUAL(err, "NOT_DISTRIBUTED");
}

BOOST_AUTO_TEST_CASE(plain_steps_greater_than_1_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoStep note;
    note.step_id = "step-note";
    note.steps = 2;
    note.want_distributed = false;
    const modelnet::SwarmNotNoStepResult result = modelnet::SwarmNoteNotNoStep(note, err);
    BOOST_CHECK(!result.distributed);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
