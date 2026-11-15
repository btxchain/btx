// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfallback.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notfallback_tests, BasicTestingSetup)

static modelnet::SwarmNotFallback NotedNote()
{
    modelnet::SwarmNotFallback note;
    note.node_id = "node-1";
    note.gpu_present = true;
    note.want_observe = false;
    note.want_train = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmNotFallback note = NotedNote();
    note.node_id.clear();
    note.gpu_present = false;
    note.want_observe = true;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotFallbackResult result = modelnet::SwarmNoteNotFallback(note, err);
    BOOST_CHECK(!result.observer_kept);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_train_with_gpu_is_cpu_only)
{
    modelnet::SwarmNotFallback note = NotedNote();
    note.gpu_present = true;
    note.want_observe = false;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotFallbackResult result = modelnet::SwarmNoteNotFallback(note, err);
    BOOST_CHECK(result.observer_kept);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "CPU_ONLY");
    BOOST_CHECK_EQUAL(err, "CPU_ONLY");
}

BOOST_AUTO_TEST_CASE(want_train_missing_gpu_keeps_observer)
{
    modelnet::SwarmNotFallback note = NotedNote();
    note.gpu_present = false;
    note.want_observe = false;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotFallbackResult result = modelnet::SwarmNoteNotFallback(note, err);
    BOOST_CHECK(result.observer_kept);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "CPU_ONLY");
    BOOST_CHECK_EQUAL(err, "CPU_ONLY");
}

BOOST_AUTO_TEST_CASE(want_train_wins_over_want_observe)
{
    modelnet::SwarmNotFallback note = NotedNote();
    note.gpu_present = false;
    note.want_observe = true;
    note.want_train = true;
    std::string err = "prior";
    const modelnet::SwarmNotFallbackResult result = modelnet::SwarmNoteNotFallback(note, err);
    BOOST_CHECK(result.observer_kept);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "CPU_ONLY");
    BOOST_CHECK_EQUAL(err, "CPU_ONLY");
}

BOOST_AUTO_TEST_CASE(want_observe_is_noted)
{
    modelnet::SwarmNotFallback note = NotedNote();
    note.gpu_present = true;
    note.want_observe = true;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotFallbackResult result = modelnet::SwarmNoteNotFallback(note, err);
    BOOST_CHECK(result.observer_kept);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(want_observe_missing_gpu_keeps_observer)
{
    modelnet::SwarmNotFallback note = NotedNote();
    note.gpu_present = false;
    note.want_observe = true;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotFallbackResult result = modelnet::SwarmNoteNotFallback(note, err);
    BOOST_CHECK(result.observer_kept);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(neither_flag_is_noted)
{
    modelnet::SwarmNotFallback note = NotedNote();
    note.gpu_present = true;
    note.want_observe = false;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotFallbackResult result = modelnet::SwarmNoteNotFallback(note, err);
    BOOST_CHECK(result.observer_kept);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(neither_flag_missing_gpu_keeps_observer)
{
    modelnet::SwarmNotFallback note = NotedNote();
    note.gpu_present = false;
    note.want_observe = false;
    note.want_train = false;
    std::string err = "prior";
    const modelnet::SwarmNotFallbackResult result = modelnet::SwarmNoteNotFallback(note, err);
    BOOST_CHECK(result.observer_kept);
    BOOST_CHECK(!result.training);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
