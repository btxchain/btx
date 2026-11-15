// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_exec/nif_exec.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(nif_exec_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(memory_batch_respects_scope_cap_and_cancel)
{
    modelnet::NifExec exec;
    std::string err;
    BOOST_CHECK(exec.Enqueue("a", modelnet::NifPrivacy::LocalOnly, "ab", "memory", err));
    BOOST_CHECK(exec.Enqueue("b", modelnet::NifPrivacy::LanOnly, "xy", "memory", err));
    BOOST_CHECK(exec.Tick(err));
    BOOST_CHECK_EQUAL(exec.held("a"), "a");
    BOOST_CHECK(exec.held("b").empty());
    BOOST_CHECK_EQUAL(exec.accepted_bytes(), static_cast<int64_t>(1));

    BOOST_CHECK(exec.Cancel("a", err));
    BOOST_CHECK_EQUAL(exec.held("a"), "a");
    BOOST_CHECK(!exec.buffer_released_early());
    BOOST_CHECK(exec.Tick(err));
    BOOST_CHECK_EQUAL(exec.held("b"), "x");
    BOOST_CHECK_EQUAL(exec.held("a"), "a");

    modelnet::NifExec full;
    BOOST_CHECK(full.Enqueue("1", modelnet::NifPrivacy::LocalOnly, "a", "memory", err));
    BOOST_CHECK(full.Enqueue("2", modelnet::NifPrivacy::LocalOnly, "a", "memory", err));
    BOOST_CHECK(full.Enqueue("3", modelnet::NifPrivacy::LocalOnly, "a", "memory", err));
    BOOST_CHECK(full.Enqueue("4", modelnet::NifPrivacy::LocalOnly, "a", "memory", err));
    BOOST_CHECK(!full.Enqueue("5", modelnet::NifPrivacy::LocalOnly, "a", "memory", err));
    BOOST_CHECK_EQUAL(err, "QUEUE");

    modelnet::NifExec absent;
    BOOST_CHECK(absent.Enqueue("v", modelnet::NifPrivacy::LocalOnly, "hello", "vllm", err));
    BOOST_CHECK(!absent.Tick(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(absent.held("v").empty());
    BOOST_CHECK_EQUAL(absent.accepted_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK(!absent.gpu());
    BOOST_CHECK_EQUAL(absent.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
