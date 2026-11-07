// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnouseful.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnouseful_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_task_id_is_task)
{
    modelnet::SwarmNotNoUseful note;
    note.want_claim = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoUsefulResult result = modelnet::SwarmNoteNotNoUseful(note, err);
    BOOST_CHECK(!result.useful);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.code, "TASK");
    BOOST_CHECK_EQUAL(err, "TASK");
}

BOOST_AUTO_TEST_CASE(want_claim_is_not_useful)
{
    modelnet::SwarmNotNoUseful note;
    note.task_id = "task-1";
    note.want_claim = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoUsefulResult result = modelnet::SwarmNoteNotNoUseful(note, err);
    BOOST_CHECK(!result.useful);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.code, "NOT_USEFUL");
    BOOST_CHECK_EQUAL(err, "NOT_USEFUL");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoUseful note;
    note.task_id = "task-1";
    note.want_claim = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoUsefulResult result = modelnet::SwarmNoteNotNoUseful(note, err);
    BOOST_CHECK(!result.useful);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
