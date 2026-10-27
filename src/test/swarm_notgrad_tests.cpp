// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notgrad.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notgrad_tests, BasicTestingSetup)

static modelnet::SwarmNotGrad NotedNote()
{
    modelnet::SwarmNotGrad note;
    note.job_id = "job-1";
    note.want_sync = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_job_id_is_job)
{
    modelnet::SwarmNotGrad note = NotedNote();
    note.job_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotGradResult result = modelnet::SwarmNoteNotGrad(note, err);
    BOOST_CHECK(!result.synced);
    BOOST_CHECK_EQUAL(result.code, "JOB");
    BOOST_CHECK_EQUAL(err, "JOB");
}

BOOST_AUTO_TEST_CASE(want_sync_is_not_synced)
{
    modelnet::SwarmNotGrad note = NotedNote();
    note.want_sync = true;
    std::string err = "prior";
    const modelnet::SwarmNotGradResult result = modelnet::SwarmNoteNotGrad(note, err);
    BOOST_CHECK(!result.synced);
    BOOST_CHECK_EQUAL(result.code, "NOT_SYNCED");
    BOOST_CHECK_EQUAL(err, "NOT_SYNCED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotGrad note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotGradResult result = modelnet::SwarmNoteNotGrad(note, err);
    BOOST_CHECK(!result.synced);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
