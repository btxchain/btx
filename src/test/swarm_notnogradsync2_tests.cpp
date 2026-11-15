// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnogradsync2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnogradsync2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoGradSync2 NotedNote()
{
    modelnet::SwarmNotNoGradSync2 note;
    note.run_id = "run-1";
    note.want_sync = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_run_id_is_run)
{
    modelnet::SwarmNotNoGradSync2 note = NotedNote();
    note.run_id.clear();
    note.want_sync = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoGradSync2Result result = modelnet::SwarmNoteNotNoGradSync2(note, err);
    BOOST_CHECK(!result.synced);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "RUN");
    BOOST_CHECK_EQUAL(err, "RUN");
}

BOOST_AUTO_TEST_CASE(want_sync_is_not_run)
{
    modelnet::SwarmNotNoGradSync2 note = NotedNote();
    note.want_sync = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoGradSync2Result result = modelnet::SwarmNoteNotNoGradSync2(note, err);
    BOOST_CHECK(!result.synced);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_RUN");
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoGradSync2 note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoGradSync2Result result = modelnet::SwarmNoteNotNoGradSync2(note, err);
    BOOST_CHECK(!result.synced);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
