// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notgpuoff.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notgpuoff_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id)
{
    modelnet::SwarmNotGpuOff note;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotGpuOffResult result = modelnet::SwarmNoteNotGpuOff(note, err);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK(!result.training);
    BOOST_CHECK(!result.checkpoint_saved);
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_train)
{
    modelnet::SwarmNotGpuOff note;
    note.node_id = "node-1";
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotGpuOffResult result = modelnet::SwarmNoteNotGpuOff(note, err);
    BOOST_CHECK_EQUAL(result.code, "GPU_OFF");
    BOOST_CHECK(!result.training);
    BOOST_CHECK(!result.checkpoint_saved);
    BOOST_CHECK_EQUAL(err, "GPU_OFF");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotGpuOff note;
    note.node_id = "node-1";
    std::string err = "prior";
    const modelnet::SwarmNotGpuOffResult result = modelnet::SwarmNoteNotGpuOff(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.training);
    BOOST_CHECK(!result.checkpoint_saved);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
