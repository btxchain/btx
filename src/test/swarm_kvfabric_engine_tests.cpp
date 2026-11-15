// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvfabric/fabric.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_kvfabric_engine_tests, BasicTestingSetup)

static void ExpectNoMove(const modelnet::SwarmKvFabric& fabric, const modelnet::SwarmKvFabricResult& result)
{
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.bytes, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(fabric.bytes_moved(), false);
}

static const char* kEngines[] = {
    "vllm",
    "sglang",
    "lmcache",
    "nixl",
    "mooncake",
    "rdma",
};

BOOST_AUTO_TEST_CASE(known_engines_absent_when_present_false)
{
    for (const char* name : kEngines) {
        modelnet::SwarmKvFabric fabric;
        const modelnet::SwarmKvFabricResult result = fabric.Probe(name, false);
        BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
        BOOST_CHECK_EQUAL(result.advertised, false);
        BOOST_CHECK_EQUAL(result.qualified, false);
        BOOST_CHECK_EQUAL(fabric.advertised(), false);
        BOOST_CHECK_EQUAL(fabric.qualified(), false);
        BOOST_CHECK_EQUAL(fabric.engine_installed(), false);
        BOOST_CHECK_EQUAL(fabric.engine_status(), "ENGINE_ABSENT");
        BOOST_CHECK_EQUAL(fabric.process_started(), false);
        ExpectNoMove(fabric, result);
    }
}

BOOST_AUTO_TEST_CASE(known_engines_installed_stay_unqualified)
{
    for (const char* name : kEngines) {
        modelnet::SwarmKvFabric fabric;
        const modelnet::SwarmKvFabricResult result = fabric.Probe(name, true);
        BOOST_REQUIRE_EQUAL(result.code, "INSTALLED");
        BOOST_CHECK_EQUAL(result.advertised, false);
        BOOST_CHECK_EQUAL(result.qualified, false);
        BOOST_CHECK_EQUAL(fabric.advertised(), false);
        BOOST_CHECK_EQUAL(fabric.qualified(), false);
        BOOST_CHECK_EQUAL(fabric.engine_installed(), true);
        BOOST_CHECK_EQUAL(fabric.engine_status(), "INSTALLED");
        BOOST_CHECK_EQUAL(fabric.process_started(), false);
        ExpectNoMove(fabric, result);
    }
}

BOOST_AUTO_TEST_CASE(unknown_name_is_absent_even_when_present)
{
    const char* unknown[] = {"", "cuda", "vLLM", "VLLM", "tensorrt", "nix", "rdma ", "lmcache2"};
    for (const char* name : unknown) {
        modelnet::SwarmKvFabric fabric;
        const modelnet::SwarmKvFabricResult flagged = fabric.Probe(name, true);
        BOOST_CHECK_EQUAL(flagged.code, "ENGINE_ABSENT");
        BOOST_CHECK_EQUAL(flagged.advertised, false);
        BOOST_CHECK_EQUAL(flagged.qualified, false);
        BOOST_CHECK_EQUAL(fabric.engine_installed(), false);
        BOOST_CHECK_EQUAL(fabric.process_started(), false);
        ExpectNoMove(fabric, flagged);

        const modelnet::SwarmKvFabricResult plain = fabric.Probe(name, false);
        BOOST_CHECK_EQUAL(plain.code, "ENGINE_ABSENT");
        BOOST_CHECK_EQUAL(plain.advertised, false);
        BOOST_CHECK_EQUAL(fabric.engine_installed(), false);
        BOOST_CHECK_EQUAL(fabric.process_started(), false);
        ExpectNoMove(fabric, plain);
    }
}

BOOST_AUTO_TEST_CASE(unknown_probe_clears_installed)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult installed = fabric.Probe("nixl", true);
    BOOST_REQUIRE_EQUAL(installed.code, "INSTALLED");
    ExpectNoMove(fabric, installed);

    const modelnet::SwarmKvFabricResult absent = fabric.Probe("not-an-engine", true);
    BOOST_CHECK_EQUAL(absent.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(fabric.engine_installed(), false);
    BOOST_CHECK_EQUAL(fabric.advertised(), false);
    BOOST_CHECK_EQUAL(fabric.qualified(), false);
    BOOST_CHECK_EQUAL(fabric.process_started(), false);
    ExpectNoMove(fabric, absent);
}

BOOST_AUTO_TEST_SUITE_END()
