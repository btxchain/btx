// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_maxsteps.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_maxsteps_tests, BasicTestingSetup)

static modelnet::SwarmMaxSteps NotedSteps()
{
    modelnet::SwarmMaxSteps note;
    note.node_id = "node-1";
    note.max_steps = 8;
    note.want_train = false;
    return note;
}

static void ExpectNotTraining(const modelnet::SwarmMaxStepsResult& result)
{
    BOOST_CHECK(!result.training);
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_steps)
{
    modelnet::SwarmMaxSteps note = NotedSteps();
    note.node_id.clear();
    std::string err = "prior";
    const modelnet::SwarmMaxStepsResult result = modelnet::SwarmNoteMaxSteps(note, err);
    ExpectNotTraining(result);
    BOOST_CHECK_EQUAL(result.code, "STEPS");
    BOOST_CHECK_EQUAL(err, "STEPS");
}

BOOST_AUTO_TEST_CASE(negative_steps_is_steps)
{
    modelnet::SwarmMaxSteps note = NotedSteps();
    note.max_steps = -1;
    std::string err = "prior";
    const modelnet::SwarmMaxStepsResult result = modelnet::SwarmNoteMaxSteps(note, err);
    ExpectNotTraining(result);
    BOOST_CHECK_EQUAL(result.code, "STEPS");
    BOOST_CHECK_EQUAL(err, "STEPS");
}

BOOST_AUTO_TEST_CASE(zero_steps_with_want_train_is_cpu_only)
{
    modelnet::SwarmMaxSteps note = NotedSteps();
    note.max_steps = 0;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmMaxStepsResult result = modelnet::SwarmNoteMaxSteps(note, err);
    ExpectNotTraining(result);
    BOOST_CHECK(note.want_train);
    BOOST_CHECK_EQUAL(result.code, "CPU_ONLY");
    BOOST_CHECK_EQUAL(err, "CPU_ONLY");
}

BOOST_AUTO_TEST_CASE(want_train_with_positive_steps_is_held)
{
    modelnet::SwarmMaxSteps note = NotedSteps();
    note.max_steps = 8;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmMaxStepsResult result = modelnet::SwarmNoteMaxSteps(note, err);
    ExpectNotTraining(result);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(positive_steps_without_want_train_is_noted)
{
    modelnet::SwarmMaxSteps note = NotedSteps();
    note.max_steps = 8;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmMaxStepsResult result = modelnet::SwarmNoteMaxSteps(note, err);
    ExpectNotTraining(result);
    BOOST_CHECK(!note.want_train);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
