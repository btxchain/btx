// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_readfence/readfence.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_readfence_prefetch_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(missing_engine_records_nothing_and_moves_no_bytes)
{
    modelnet::SwarmReadFence fence;
    std::string err = "prior";

    BOOST_REQUIRE(!fence.Prefetch("page", err));
    BOOST_REQUIRE_EQUAL(err, "ENGINE_ABSENT");
    BOOST_REQUIRE(!fence.prefetched("page"));
    BOOST_REQUIRE_EQUAL(fence.prefetch_count(), 0u);
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    BOOST_REQUIRE(!fence.cuda_buffer());
    BOOST_REQUIRE(!fence.process_started());
    BOOST_REQUIRE(!fence.installed());

    err = "prior";
    BOOST_REQUIRE(!fence.Probe("vllm", false, err));
    BOOST_REQUIRE_EQUAL(err, "ENGINE_ABSENT");

    err = "prior";
    BOOST_REQUIRE(!fence.Prefetch("page", err));
    BOOST_REQUIRE_EQUAL(err, "ENGINE_ABSENT");
    BOOST_REQUIRE(!fence.prefetched("page"));
    BOOST_REQUIRE_EQUAL(fence.prefetch_count(), 0u);
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    BOOST_REQUIRE(!fence.cuda_buffer());

    err = "prior";
    BOOST_REQUIRE(!fence.Prefetch("", err));
    BOOST_REQUIRE_EQUAL(err, "ENGINE_ABSENT");
    BOOST_REQUIRE_EQUAL(fence.prefetch_count(), 0u);
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    BOOST_REQUIRE(!fence.cuda_buffer());
}

BOOST_AUTO_TEST_CASE(installed_engine_records_the_page_id)
{
    modelnet::SwarmReadFence fence;
    std::string err = "prior";

    BOOST_REQUIRE(fence.Probe("sglang", true, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(fence.installed());
    BOOST_REQUIRE(!fence.qualified());
    BOOST_REQUIRE(!fence.advertised());
    BOOST_REQUIRE(!fence.process_started());

    err = "prior";
    BOOST_REQUIRE(fence.Prefetch("", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(fence.prefetched(""));
    BOOST_REQUIRE_EQUAL(fence.prefetch_count(), 1u);
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    BOOST_REQUIRE(!fence.cuda_buffer());

    err = "prior";
    BOOST_REQUIRE(fence.Prefetch("page", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(fence.prefetched("page"));
    BOOST_REQUIRE_EQUAL(fence.prefetch_count(), 2u);
    BOOST_REQUIRE(!fence.placed("page"));
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    BOOST_REQUIRE(!fence.cuda_buffer());
    BOOST_REQUIRE(!fence.process_started());

    BOOST_REQUIRE(fence.Prefetch("page", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(fence.prefetch_count(), 2u);
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    BOOST_REQUIRE(!fence.cuda_buffer());

    BOOST_REQUIRE(fence.Prefetch("other", err));
    BOOST_REQUIRE_EQUAL(fence.prefetch_count(), 3u);
    BOOST_REQUIRE(fence.prefetched("other"));
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    BOOST_REQUIRE(!fence.cuda_buffer());
}

BOOST_AUTO_TEST_SUITE_END()
