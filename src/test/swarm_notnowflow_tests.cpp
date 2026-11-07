// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnowflow.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnowflow_tests, BasicTestingSetup)

static modelnet::SwarmNotNoWflow NotedNote()
{
    modelnet::SwarmNotNoWflow note;
    note.workflow_id = "workflow-1";
    note.want_launch = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_workflow_id_is_workflow)
{
    modelnet::SwarmNotNoWflow note = NotedNote();
    note.workflow_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotNoWflowResult result = modelnet::SwarmNoteNotNoWflow(note, err);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "WORKFLOW");
    BOOST_CHECK_EQUAL(err, "WORKFLOW");
}

BOOST_AUTO_TEST_CASE(want_launch_is_not_launched)
{
    modelnet::SwarmNotNoWflow note = NotedNote();
    note.want_launch = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoWflowResult result = modelnet::SwarmNoteNotNoWflow(note, err);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_LAUNCHED");
    BOOST_CHECK_EQUAL(err, "NOT_LAUNCHED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoWflow note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoWflowResult result = modelnet::SwarmNoteNotNoWflow(note, err);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
