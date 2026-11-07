// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoschedkey.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoschedkey_tests, BasicTestingSetup)

static modelnet::SwarmNotNoSchedKey NotedNote()
{
    modelnet::SwarmNotNoSchedKey note;
    note.scheduler_id = "scheduler-1";
    note.scheduler = false;
    note.want_spend = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_scheduler_id_is_scheduler)
{
    modelnet::SwarmNotNoSchedKey note = NotedNote();
    note.scheduler_id.clear();
    note.scheduler = true;
    note.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSchedKeyResult result = modelnet::SwarmNoteNotNoSchedKey(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "SCHEDULER");
    BOOST_CHECK_EQUAL(err, "SCHEDULER");
}

BOOST_AUTO_TEST_CASE(scheduler_true_is_no_spend)
{
    modelnet::SwarmNotNoSchedKey note = NotedNote();
    note.scheduler = true;
    note.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSchedKeyResult result = modelnet::SwarmNoteNotNoSchedKey(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NO_SPEND");
    BOOST_CHECK_EQUAL(err, "NO_SPEND");
}

BOOST_AUTO_TEST_CASE(want_spend_is_no_spend)
{
    modelnet::SwarmNotNoSchedKey note = NotedNote();
    note.scheduler = false;
    note.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSchedKeyResult result = modelnet::SwarmNoteNotNoSchedKey(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NO_SPEND");
    BOOST_CHECK_EQUAL(err, "NO_SPEND");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoSchedKey note = NotedNote();
    note.scheduler = false;
    note.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSchedKeyResult result = modelnet::SwarmNoteNotNoSchedKey(note, err);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
