// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocap1.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocap1_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id)
{
    modelnet::SwarmNotNoCap1 note;
    note.thread_count = 0;
    note.want_apply = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCap1Result result = modelnet::SwarmNoteNotNoCap1(note, err);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK(!result.applied);
    BOOST_CHECK_EQUAL(result.threads, 0);
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(thread_count_below_1)
{
    modelnet::SwarmNotNoCap1 note;
    note.node_id = "node-1";
    note.thread_count = 0;
    note.want_apply = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCap1Result result = modelnet::SwarmNoteNotNoCap1(note, err);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK(!result.applied);
    BOOST_CHECK_EQUAL(result.threads, 0);
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(want_apply_at_1)
{
    modelnet::SwarmNotNoCap1 note;
    note.node_id = "node-1";
    note.thread_count = 1;
    note.want_apply = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCap1Result result = modelnet::SwarmNoteNotNoCap1(note, err);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK(!result.applied);
    BOOST_CHECK_EQUAL(result.threads, 0);
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(plain_1)
{
    modelnet::SwarmNotNoCap1 note;
    note.node_id = "node-1";
    note.thread_count = 1;
    note.want_apply = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCap1Result result = modelnet::SwarmNoteNotNoCap1(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.applied);
    BOOST_CHECK_EQUAL(result.threads, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
