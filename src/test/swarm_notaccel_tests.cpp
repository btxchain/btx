// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notaccel.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notaccel_tests, BasicTestingSetup)

static modelnet::SwarmNotAccel NotedNote()
{
    modelnet::SwarmNotAccel note;
    note.node_id = "node-1";
    note.gpu_present = true;
    note.want_train = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmNotAccel note = NotedNote();
    note.node_id.clear();
    note.gpu_present = true;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotAccelResult result = modelnet::SwarmNoteNotAccel(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(missing_gpu_is_cpu_only)
{
    modelnet::SwarmNotAccel note = NotedNote();
    note.gpu_present = false;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotAccelResult result = modelnet::SwarmNoteNotAccel(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "CPU_ONLY");
    BOOST_CHECK_EQUAL(err, "CPU_ONLY");
}

BOOST_AUTO_TEST_CASE(missing_gpu_and_want_train_is_cpu_only)
{
    modelnet::SwarmNotAccel note = NotedNote();
    note.gpu_present = false;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotAccelResult result = modelnet::SwarmNoteNotAccel(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "CPU_ONLY");
    BOOST_CHECK_EQUAL(err, "CPU_ONLY");
}

BOOST_AUTO_TEST_CASE(gpu_present_want_train_is_cpu_only)
{
    modelnet::SwarmNotAccel note = NotedNote();
    note.gpu_present = true;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotAccelResult result = modelnet::SwarmNoteNotAccel(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "CPU_ONLY");
    BOOST_CHECK_EQUAL(err, "CPU_ONLY");
}

BOOST_AUTO_TEST_CASE(gpu_present_without_want_train_is_noted)
{
    modelnet::SwarmNotAccel note = NotedNote();
    note.gpu_present = true;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotAccelResult result = modelnet::SwarmNoteNotAccel(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
