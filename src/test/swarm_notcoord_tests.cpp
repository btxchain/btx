// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcoord.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notcoord_tests, BasicTestingSetup)

static modelnet::SwarmNotCoord NotedNote()
{
    modelnet::SwarmNotCoord note;
    note.task_id = "task-1";
    note.want_run = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_task_id_is_task)
{
    modelnet::SwarmNotCoord note = NotedNote();
    note.task_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotCoordResult result = modelnet::SwarmNoteNotCoord(note, err);
    BOOST_CHECK(!result.ran);
    BOOST_CHECK_EQUAL(result.code, "TASK");
    BOOST_CHECK_EQUAL(err, "TASK");
}

BOOST_AUTO_TEST_CASE(want_run_is_not_run)
{
    modelnet::SwarmNotCoord note = NotedNote();
    note.want_run = true;
    std::string err = "prior";
    const modelnet::SwarmNotCoordResult result = modelnet::SwarmNoteNotCoord(note, err);
    BOOST_CHECK(!result.ran);
    BOOST_CHECK_EQUAL(result.code, "NOT_RUN");
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotCoord note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotCoordResult result = modelnet::SwarmNoteNotCoord(note, err);
    BOOST_CHECK(!result.ran);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
