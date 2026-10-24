// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnogpucrash.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnogpucrash_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_run_id)
{
    modelnet::SwarmNotNoGpuCrash note;
    note.gpu_crash = true;
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoGpuCrashResult result = modelnet::SwarmNoteNotNoGpuCrash(note, err);
    BOOST_CHECK_EQUAL(result.code, "RUN");
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.gpu);
    BOOST_CHECK_EQUAL(err, "RUN");
}

BOOST_AUTO_TEST_CASE(gpu_crash)
{
    modelnet::SwarmNotNoGpuCrash note;
    note.run_id = "run-1";
    note.gpu_crash = true;
    note.want_publish = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoGpuCrashResult result = modelnet::SwarmNoteNotNoGpuCrash(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_RUN");
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.gpu);
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
}

BOOST_AUTO_TEST_CASE(want_publish)
{
    modelnet::SwarmNotNoGpuCrash note;
    note.run_id = "run-1";
    note.gpu_crash = false;
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoGpuCrashResult result = modelnet::SwarmNoteNotNoGpuCrash(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_RUN");
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.gpu);
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotNoGpuCrash note;
    note.run_id = "run-1";
    note.gpu_crash = false;
    note.want_publish = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoGpuCrashResult result = modelnet::SwarmNoteNotNoGpuCrash(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.gpu);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
