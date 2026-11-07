// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notvramzero.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notvramzero_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmNotVramZero note;
    note.vram_mib = 1;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotVramZeroResult result = modelnet::SwarmNoteNotVramZero(note, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.applied_vram, 0);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(vram_mib_one_is_cpu_only)
{
    modelnet::SwarmNotVramZero note;
    note.node_id = "node-1";
    note.vram_mib = 1;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotVramZeroResult result = modelnet::SwarmNoteNotVramZero(note, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.applied_vram, 0);
    BOOST_CHECK_EQUAL(result.code, "CPU_ONLY");
    BOOST_CHECK_EQUAL(err, "CPU_ONLY");
}

BOOST_AUTO_TEST_CASE(vram_zero_want_train_is_cpu_only)
{
    modelnet::SwarmNotVramZero note;
    note.node_id = "node-1";
    note.vram_mib = 0;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotVramZeroResult result = modelnet::SwarmNoteNotVramZero(note, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.applied_vram, 0);
    BOOST_CHECK_EQUAL(result.code, "CPU_ONLY");
    BOOST_CHECK_EQUAL(err, "CPU_ONLY");
}

BOOST_AUTO_TEST_CASE(vram_zero_plain_is_noted)
{
    modelnet::SwarmNotVramZero note;
    BOOST_CHECK_EQUAL(note.vram_mib, 0);
    BOOST_CHECK(!note.want_train);
    note.node_id = "node-1";
    std::string err = "prior";
    const modelnet::SwarmNotVramZeroResult result = modelnet::SwarmNoteNotVramZero(note, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.applied_vram, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
