// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notworkflow.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notworkflow_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_workflow_id)
{
    modelnet::SwarmNotWorkflow note;
    note.want_complete = true;
    std::string err = "prior";
    const modelnet::SwarmNotWorkflowResult result = modelnet::SwarmNoteNotWorkflow(note, err);
    BOOST_CHECK_EQUAL(result.code, "TASK");
    BOOST_CHECK(!result.completed);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(err, "TASK");
}

BOOST_AUTO_TEST_CASE(want_complete)
{
    modelnet::SwarmNotWorkflow note;
    note.workflow_id = "workflow-1";
    note.want_complete = true;
    std::string err = "prior";
    const modelnet::SwarmNotWorkflowResult result = modelnet::SwarmNoteNotWorkflow(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_RUN");
    BOOST_CHECK(!result.completed);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotWorkflow note;
    note.workflow_id = "workflow-1";
    std::string err = "prior";
    const modelnet::SwarmNotWorkflowResult result = modelnet::SwarmNoteNotWorkflow(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.completed);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
