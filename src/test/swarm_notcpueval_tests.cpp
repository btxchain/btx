// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcpueval.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notcpueval_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id)
{
    modelnet::SwarmNotCpuEval note;
    note.device_present = true;
    note.want_gpu = true;
    std::string err = "prior";
    const modelnet::SwarmNotCpuEvalResult result = modelnet::SwarmNoteNotCpuEval(note, err);
    BOOST_CHECK(!result.gpu_training);
    BOOST_CHECK(!result.evaluated);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(absent_device)
{
    modelnet::SwarmNotCpuEval note;
    note.node_id = "node-1";
    note.device_present = false;
    note.want_gpu = false;
    std::string err = "prior";
    const modelnet::SwarmNotCpuEvalResult result = modelnet::SwarmNoteNotCpuEval(note, err);
    BOOST_CHECK(!result.gpu_training);
    BOOST_CHECK(!result.evaluated);
    BOOST_CHECK_EQUAL(result.code, "CPU_EVAL");
    BOOST_CHECK_EQUAL(err, "CPU_EVAL");
}

BOOST_AUTO_TEST_CASE(present_device_want_gpu)
{
    modelnet::SwarmNotCpuEval note;
    note.node_id = "node-1";
    note.device_present = true;
    note.want_gpu = true;
    std::string err = "prior";
    const modelnet::SwarmNotCpuEvalResult result = modelnet::SwarmNoteNotCpuEval(note, err);
    BOOST_CHECK(!result.gpu_training);
    BOOST_CHECK(!result.evaluated);
    BOOST_CHECK_EQUAL(result.code, "CPU_EVAL");
    BOOST_CHECK_EQUAL(err, "CPU_EVAL");
}

BOOST_AUTO_TEST_CASE(present_device_plain)
{
    modelnet::SwarmNotCpuEval note;
    BOOST_CHECK(!note.device_present);
    BOOST_CHECK(!note.want_gpu);
    note.node_id = "node-1";
    note.device_present = true;
    std::string err = "prior";
    const modelnet::SwarmNotCpuEvalResult result = modelnet::SwarmNoteNotCpuEval(note, err);
    BOOST_CHECK(!result.gpu_training);
    BOOST_CHECK(!result.evaluated);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
