// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnogpu.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnogpu_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_step_id)
{
    modelnet::SwarmNotNoGpu note;
    std::string err = "prior";
    const modelnet::SwarmNotNoGpuResult result = modelnet::SwarmNoteNotNoGpu(note, err);
    BOOST_CHECK_EQUAL(result.trained, false);
    BOOST_CHECK_EQUAL(result.used, 0);
    BOOST_CHECK_EQUAL(result.code, "STEP");
    BOOST_CHECK_EQUAL(err, "STEP");
}

BOOST_AUTO_TEST_CASE(gpu_count_0)
{
    modelnet::SwarmNotNoGpu note;
    note.step_id = "step-1";
    note.gpu_count = 0;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoGpuResult result = modelnet::SwarmNoteNotNoGpu(note, err);
    BOOST_CHECK_EQUAL(result.trained, false);
    BOOST_CHECK_EQUAL(result.used, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_RUN");
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
}

BOOST_AUTO_TEST_CASE(gpu_count_2)
{
    modelnet::SwarmNotNoGpu note;
    note.step_id = "step-1";
    note.gpu_count = 2;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoGpuResult result = modelnet::SwarmNoteNotNoGpu(note, err);
    BOOST_CHECK_EQUAL(result.trained, false);
    BOOST_CHECK_EQUAL(result.used, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_RUN");
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
}

BOOST_AUTO_TEST_CASE(gpu_count_1_want_train)
{
    modelnet::SwarmNotNoGpu note;
    note.step_id = "step-1";
    note.gpu_count = 1;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoGpuResult result = modelnet::SwarmNoteNotNoGpu(note, err);
    BOOST_CHECK_EQUAL(result.trained, false);
    BOOST_CHECK_EQUAL(result.used, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_RUN");
    BOOST_CHECK_EQUAL(err, "NOT_RUN");
}

BOOST_AUTO_TEST_CASE(gpu_count_1_plain)
{
    modelnet::SwarmNotNoGpu note;
    note.step_id = "step-1";
    note.gpu_count = 1;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoGpuResult result = modelnet::SwarmNoteNotNoGpu(note, err);
    BOOST_CHECK_EQUAL(result.trained, false);
    BOOST_CHECK_EQUAL(result.used, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
