// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrdma.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notrdma_tests, BasicTestingSetup)

static modelnet::SwarmNotRdma NotedNote()
{
    modelnet::SwarmNotRdma note;
    note.page_id = "page-1";
    note.rdma_present = true;
    note.want_transfer = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_page_id_is_rdma)
{
    modelnet::SwarmNotRdma note = NotedNote();
    note.page_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotRdmaResult result = modelnet::SwarmNoteNotRdma(note, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "RDMA");
    BOOST_CHECK_EQUAL(err, "RDMA");
}

BOOST_AUTO_TEST_CASE(want_transfer_without_rdma_is_engine_absent)
{
    modelnet::SwarmNotRdma note = NotedNote();
    note.rdma_present = false;
    note.want_transfer = true;
    std::string err = "prior";
    const modelnet::SwarmNotRdmaResult result = modelnet::SwarmNoteNotRdma(note, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(want_transfer_with_rdma_is_held)
{
    modelnet::SwarmNotRdma note = NotedNote();
    note.rdma_present = true;
    note.want_transfer = true;
    std::string err = "prior";
    const modelnet::SwarmNotRdmaResult result = modelnet::SwarmNoteNotRdma(note, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(rdma_without_want_transfer_is_noted)
{
    modelnet::SwarmNotRdma note = NotedNote();
    note.rdma_present = true;
    note.want_transfer = false;
    std::string err = "prior";
    const modelnet::SwarmNotRdmaResult result = modelnet::SwarmNoteNotRdma(note, err);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
