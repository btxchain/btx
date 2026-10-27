// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notminthread.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notminthread_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id)
{
    modelnet::SwarmNotMinThread note;
    note.thread_count = 1;
    note.want_apply = true;
    std::string err = "prior";
    const modelnet::SwarmNotMinThreadResult result = modelnet::SwarmNoteNotMinThread(note, err);
    BOOST_CHECK(!result.applied);
    BOOST_CHECK_EQUAL(result.applied_threads, 0);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(thread_count_0)
{
    modelnet::SwarmNotMinThread note;
    note.node_id = "node-1";
    note.thread_count = 0;
    note.want_apply = false;
    std::string err = "prior";
    const modelnet::SwarmNotMinThreadResult result = modelnet::SwarmNoteNotMinThread(note, err);
    BOOST_CHECK(!result.applied);
    BOOST_CHECK_EQUAL(result.applied_threads, 0);
    BOOST_CHECK_EQUAL(result.code, "FLOOR");
    BOOST_CHECK_EQUAL(err, "FLOOR");
}

BOOST_AUTO_TEST_CASE(thread_count_1_with_want_apply)
{
    modelnet::SwarmNotMinThread note;
    note.node_id = "node-1";
    note.thread_count = 1;
    note.want_apply = true;
    std::string err = "prior";
    const modelnet::SwarmNotMinThreadResult result = modelnet::SwarmNoteNotMinThread(note, err);
    BOOST_CHECK(!result.applied);
    BOOST_CHECK_EQUAL(result.applied_threads, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(thread_count_1_plain)
{
    modelnet::SwarmNotMinThread note;
    note.node_id = "node-1";
    note.thread_count = 1;
    note.want_apply = false;
    std::string err = "prior";
    const modelnet::SwarmNotMinThreadResult result = modelnet::SwarmNoteNotMinThread(note, err);
    BOOST_CHECK(!result.applied);
    BOOST_CHECK_EQUAL(result.applied_threads, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
