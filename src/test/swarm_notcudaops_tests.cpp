// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcudaops.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notcudaops_tests, BasicTestingSetup)

static modelnet::SwarmNotCudaOps NotedNote()
{
    modelnet::SwarmNotCudaOps note;
    note.engine_id = "engine-1";
    note.ops_present = true;
    note.want_transfer = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_engine_id_is_engine)
{
    modelnet::SwarmNotCudaOps note = NotedNote();
    note.engine_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotCudaOpsResult result = modelnet::SwarmNoteNotCudaOps(note, err);
    BOOST_CHECK(!result.transferred);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ENGINE");
    BOOST_CHECK_EQUAL(err, "ENGINE");
}

BOOST_AUTO_TEST_CASE(ops_absent_without_want_transfer)
{
    modelnet::SwarmNotCudaOps note = NotedNote();
    note.ops_present = false;
    note.want_transfer = false;
    std::string err = "prior";
    const modelnet::SwarmNotCudaOpsResult result = modelnet::SwarmNoteNotCudaOps(note, err);
    BOOST_CHECK(!result.transferred);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(ops_present_with_want_transfer_is_engine_absent)
{
    modelnet::SwarmNotCudaOps note = NotedNote();
    note.ops_present = true;
    note.want_transfer = true;
    std::string err = "prior";
    const modelnet::SwarmNotCudaOpsResult result = modelnet::SwarmNoteNotCudaOps(note, err);
    BOOST_CHECK(!result.transferred);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(ops_present_plain_is_noted)
{
    modelnet::SwarmNotCudaOps note = NotedNote();
    note.ops_present = true;
    note.want_transfer = false;
    std::string err = "prior";
    const modelnet::SwarmNotCudaOpsResult result = modelnet::SwarmNoteNotCudaOps(note, err);
    BOOST_CHECK(!result.transferred);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
