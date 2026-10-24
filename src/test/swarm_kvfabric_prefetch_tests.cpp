// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvfabric/fabric.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_kvfabric_prefetch_tests, BasicTestingSetup)

static void ExpectNoMove(const modelnet::SwarmKvFabric& fabric, const modelnet::SwarmKvFabricResult& result)
{
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.bytes, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(fabric.bytes_moved(), false);
}

BOOST_AUTO_TEST_CASE(prefetch_before_probe_is_absent)
{
    modelnet::SwarmKvFabric fabric;
    BOOST_CHECK_EQUAL(fabric.engine_installed(), false);
    const modelnet::SwarmKvFabricResult result = fabric.Prefetch("page-1");
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK(!fabric.prefetched("page-1"));
    BOOST_CHECK(!fabric.cuda_buffer());
    ExpectNoMove(fabric, result);
}

BOOST_AUTO_TEST_CASE(prefetch_when_present_false_is_absent)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult probe = fabric.Probe("sglang", false);
    BOOST_CHECK_EQUAL(probe.code, "ENGINE_ABSENT");
    ExpectNoMove(fabric, probe);

    const modelnet::SwarmKvFabricResult result = fabric.Prefetch("page-1");
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK(!fabric.prefetched("page-1"));
    BOOST_CHECK(!fabric.cuda_buffer());
    ExpectNoMove(fabric, result);
}

BOOST_AUTO_TEST_CASE(prefetch_when_unknown_engine_is_absent)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult probe = fabric.Probe("cuda", true);
    BOOST_CHECK_EQUAL(probe.code, "ENGINE_ABSENT");
    ExpectNoMove(fabric, probe);

    const modelnet::SwarmKvFabricResult result = fabric.Prefetch("page-1");
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK(!fabric.prefetched("page-1"));
    BOOST_CHECK(!fabric.cuda_buffer());
    ExpectNoMove(fabric, result);
}

BOOST_AUTO_TEST_CASE(installed_prefetch_records_page)
{
    static const char* kEngines[] = {"vllm", "sglang", "lmcache", "nixl", "mooncake", "rdma"};
    for (const char* name : kEngines) {
        modelnet::SwarmKvFabric fabric;
        const modelnet::SwarmKvFabricResult probe = fabric.Probe(name, true);
        BOOST_REQUIRE_EQUAL(probe.code, "INSTALLED");
        BOOST_CHECK_EQUAL(probe.qualified, false);
        BOOST_CHECK_EQUAL(probe.advertised, false);
        ExpectNoMove(fabric, probe);

        const modelnet::SwarmKvFabricResult empty = fabric.Prefetch("");
        BOOST_CHECK_EQUAL(empty.code, "PAGE");
        BOOST_CHECK(!fabric.prefetched(""));
        BOOST_CHECK(!fabric.cuda_buffer());
        ExpectNoMove(fabric, empty);

        const modelnet::SwarmKvFabricResult result = fabric.Prefetch("page-1");
        BOOST_REQUIRE_EQUAL(result.code, "PREFETCH");
        BOOST_CHECK(fabric.prefetched("page-1"));
        BOOST_CHECK(!fabric.cuda_buffer());
        ExpectNoMove(fabric, result);
    }
}

BOOST_AUTO_TEST_CASE(prefetch_does_not_require_placement)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult probe = fabric.Probe("lmcache", true);
    BOOST_REQUIRE_EQUAL(probe.code, "INSTALLED");
    ExpectNoMove(fabric, probe);

    const modelnet::SwarmKvFabricResult result = fabric.Prefetch("page-unplaced");
    BOOST_REQUIRE_EQUAL(result.code, "PREFETCH");
    BOOST_CHECK(fabric.prefetched("page-unplaced"));
    BOOST_CHECK(!fabric.placed("page-unplaced"));
    BOOST_CHECK(!fabric.cuda_buffer());
    ExpectNoMove(fabric, result);
}

BOOST_AUTO_TEST_CASE(losing_installed_stops_new_prefetch)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult probe = fabric.Probe("mooncake", true);
    BOOST_REQUIRE_EQUAL(probe.code, "INSTALLED");
    ExpectNoMove(fabric, probe);

    const modelnet::SwarmKvFabricResult first = fabric.Prefetch("page-1");
    BOOST_REQUIRE_EQUAL(first.code, "PREFETCH");
    BOOST_CHECK(fabric.prefetched("page-1"));
    ExpectNoMove(fabric, first);

    const modelnet::SwarmKvFabricResult absent = fabric.Probe("mooncake", false);
    BOOST_CHECK_EQUAL(absent.code, "ENGINE_ABSENT");
    ExpectNoMove(fabric, absent);

    const modelnet::SwarmKvFabricResult second = fabric.Prefetch("page-2");
    BOOST_CHECK_EQUAL(second.code, "ENGINE_ABSENT");
    BOOST_CHECK(!fabric.prefetched("page-2"));
    BOOST_CHECK(fabric.prefetched("page-1"));
    BOOST_CHECK(!fabric.cuda_buffer());
    ExpectNoMove(fabric, second);
}

BOOST_AUTO_TEST_SUITE_END()
