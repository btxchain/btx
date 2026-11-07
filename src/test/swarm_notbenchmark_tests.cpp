// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notbenchmark.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notbenchmark_tests, BasicTestingSetup)

static modelnet::SwarmNotBenchmark NotedNote()
{
    modelnet::SwarmNotBenchmark note;
    note.node_id = "node-1";
    note.tokens_per_sec = 100;
    note.want_publish = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_rate)
{
    modelnet::SwarmNotBenchmark note = NotedNote();
    note.node_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotBenchmarkResult result = modelnet::SwarmNoteNotBenchmark(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.measured);
    BOOST_CHECK_EQUAL(result.code, "RATE");
    BOOST_CHECK_EQUAL(err, "RATE");
}

BOOST_AUTO_TEST_CASE(negative_rate_is_rate)
{
    modelnet::SwarmNotBenchmark note = NotedNote();
    note.tokens_per_sec = -1;
    std::string err = "prior";
    const modelnet::SwarmNotBenchmarkResult result = modelnet::SwarmNoteNotBenchmark(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.measured);
    BOOST_CHECK_EQUAL(result.code, "RATE");
    BOOST_CHECK_EQUAL(err, "RATE");
}

BOOST_AUTO_TEST_CASE(want_publish_with_tokens_is_unmeasured)
{
    modelnet::SwarmNotBenchmark note = NotedNote();
    note.tokens_per_sec = 100;
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotBenchmarkResult result = modelnet::SwarmNoteNotBenchmark(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.measured);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(tokens_without_want_publish_is_noted)
{
    modelnet::SwarmNotBenchmark note = NotedNote();
    note.tokens_per_sec = 100;
    note.want_publish = false;
    std::string err = "prior";
    const modelnet::SwarmNotBenchmarkResult result = modelnet::SwarmNoteNotBenchmark(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.measured);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
