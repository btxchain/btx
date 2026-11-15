// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoseedcpu.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoseedcpu_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id)
{
    modelnet::SwarmNotNoSeedCpu note;
    note.no_device = true;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSeedCpuResult result = modelnet::SwarmNoteNotNoSeedCpu(note, err);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.gpu);
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(no_device)
{
    modelnet::SwarmNotNoSeedCpu note;
    note.node_id = "node-1";
    note.no_device = true;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSeedCpuResult result = modelnet::SwarmNoteNotNoSeedCpu(note, err);
    BOOST_CHECK_EQUAL(result.code, "CPU_ONLY");
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.gpu);
    BOOST_CHECK_EQUAL(err, "CPU_ONLY");
}

BOOST_AUTO_TEST_CASE(want_train)
{
    modelnet::SwarmNotNoSeedCpu note;
    note.node_id = "node-1";
    note.no_device = false;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSeedCpuResult result = modelnet::SwarmNoteNotNoSeedCpu(note, err);
    BOOST_CHECK_EQUAL(result.code, "OFF");
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.gpu);
    BOOST_CHECK_EQUAL(err, "OFF");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotNoSeedCpu note;
    note.node_id = "node-1";
    note.no_device = false;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSeedCpuResult result = modelnet::SwarmNoteNotNoSeedCpu(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.trained);
    BOOST_CHECK(!result.gpu);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
