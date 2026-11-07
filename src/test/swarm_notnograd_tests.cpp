// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnograd.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnograd_tests, BasicTestingSetup)

static modelnet::SwarmNotNoGrad NotedNote()
{
    modelnet::SwarmNotNoGrad note;
    note.step_id = "step-1";
    note.want_sync = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_step_id_is_step)
{
    modelnet::SwarmNotNoGrad note = NotedNote();
    note.step_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotNoGradResult result = modelnet::SwarmNoteNotNoGrad(note, err);
    BOOST_CHECK(!result.synced);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "STEP");
    BOOST_CHECK_EQUAL(err, "STEP");
}

BOOST_AUTO_TEST_CASE(want_sync_is_not_synced)
{
    modelnet::SwarmNotNoGrad note = NotedNote();
    note.want_sync = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoGradResult result = modelnet::SwarmNoteNotNoGrad(note, err);
    BOOST_CHECK(!result.synced);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_SYNCED");
    BOOST_CHECK_EQUAL(err, "NOT_SYNCED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoGrad note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoGradResult result = modelnet::SwarmNoteNotNoGrad(note, err);
    BOOST_CHECK(!result.synced);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
