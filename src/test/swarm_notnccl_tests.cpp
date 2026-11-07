// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnccl.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnccl_tests, BasicTestingSetup)

static modelnet::SwarmNotNccl NotedNote()
{
    modelnet::SwarmNotNccl note;
    note.job_id = "job-1";
    note.want_sync = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_job_id_is_job)
{
    modelnet::SwarmNotNccl note = NotedNote();
    note.job_id.clear();
    note.want_sync = true;
    std::string err = "prior";
    const modelnet::SwarmNotNcclResult result = modelnet::SwarmNoteNotNccl(note, err);
    BOOST_CHECK_EQUAL(result.code, "JOB");
    BOOST_CHECK(!result.synced);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(err, "JOB");
}

BOOST_AUTO_TEST_CASE(want_sync_is_engine_absent)
{
    modelnet::SwarmNotNccl note = NotedNote();
    note.want_sync = true;
    std::string err = "prior";
    const modelnet::SwarmNotNcclResult result = modelnet::SwarmNoteNotNccl(note, err);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK(!result.synced);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNccl note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNcclResult result = modelnet::SwarmNoteNotNccl(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.synced);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
