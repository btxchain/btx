// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_infer/metrics.h>
#include <modelnet/swarm_infer/text_slot.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_infer_text_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_text_stores_nothing)
{
    modelnet::SwarmInferTextSlot slot;
    slot.occupied = true;
    slot.value = "kept";
    std::string err = "prior";
    const std::string code = modelnet::SwarmInferStoreText(slot, "", err);
    BOOST_CHECK_EQUAL(code, "TEXT");
    BOOST_CHECK_EQUAL(err, "TEXT");
    BOOST_REQUIRE(slot.occupied);
    BOOST_REQUIRE_EQUAL(slot.value, "kept");
}

BOOST_AUTO_TEST_CASE(first_text_is_stored)
{
    modelnet::SwarmInferTextSlot slot;
    std::string err = "prior";
    const std::string code = modelnet::SwarmInferStoreText(slot, "hello", err);
    BOOST_REQUIRE_EQUAL(code, "STORED");
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(slot.occupied);
    BOOST_REQUIRE_EQUAL(slot.value, "hello");
}

BOOST_AUTO_TEST_CASE(same_text_is_replay)
{
    modelnet::SwarmInferTextSlot slot;
    std::string err;
    BOOST_REQUIRE_EQUAL(modelnet::SwarmInferStoreText(slot, "hello", err), "STORED");
    const std::string code = modelnet::SwarmInferStoreText(slot, "hello", err);
    BOOST_REQUIRE_EQUAL(code, "REPLAY");
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(slot.value, "hello");
}

BOOST_AUTO_TEST_CASE(different_text_is_conflict_and_keeps_the_first)
{
    modelnet::SwarmInferTextSlot slot;
    std::string err;
    BOOST_REQUIRE_EQUAL(modelnet::SwarmInferStoreText(slot, "first", err), "STORED");
    const std::string code = modelnet::SwarmInferStoreText(slot, "second", err);
    BOOST_CHECK_EQUAL(code, "CONFLICT");
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_REQUIRE_EQUAL(slot.value, "first");
}

BOOST_AUTO_TEST_CASE(streamed_text_is_not_a_rate_or_latency)
{
    const std::string streamed = "tok/s=80 p50=12 p95=40 ttft=3";
    const modelnet::SwarmInferMetrics metrics = modelnet::SwarmInferMetricsFromText(streamed);
    BOOST_REQUIRE_EQUAL(metrics.tokens_per_sec, -1.0);
    BOOST_REQUIRE_EQUAL(metrics.p50_ms, -1.0);
    BOOST_REQUIRE_EQUAL(metrics.p95_ms, -1.0);
    BOOST_REQUIRE_EQUAL(metrics.ttft_ms, -1.0);
    BOOST_REQUIRE_EQUAL(metrics.bytes_moved, 0);
    BOOST_REQUIRE(!metrics.published);
    BOOST_REQUIRE(!streamed.empty());
}

BOOST_AUTO_TEST_SUITE_END()
