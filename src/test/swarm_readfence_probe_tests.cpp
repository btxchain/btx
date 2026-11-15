// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_readfence/readfence.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_readfence_probe_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(absent_engine_is_not_installed)
{
    modelnet::SwarmReadFence fence;
    std::string err = "prior";

    BOOST_REQUIRE(!fence.installed());
    BOOST_REQUIRE(fence.engine_name().empty());
    BOOST_REQUIRE(fence.engine_status().empty());
    BOOST_REQUIRE(!fence.qualified());
    BOOST_REQUIRE(!fence.advertised());
    BOOST_REQUIRE(!fence.process_started());
    BOOST_REQUIRE(!fence.cuda_buffer());
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);

    BOOST_REQUIRE(!fence.Probe("vllm", false, err));
    BOOST_REQUIRE_EQUAL(err, "ENGINE_ABSENT");
    BOOST_REQUIRE(!fence.installed());
    BOOST_REQUIRE(fence.engine_name().empty());
    BOOST_REQUIRE(fence.engine_status().empty());
    BOOST_REQUIRE(!fence.qualified());
    BOOST_REQUIRE(!fence.advertised());
    BOOST_REQUIRE(!fence.process_started());
    BOOST_REQUIRE(!fence.cuda_buffer());
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(fence.prefetch_count(), 0u);
}

BOOST_AUTO_TEST_CASE(unknown_name_is_engine_absent)
{
    modelnet::SwarmReadFence fence;
    std::string err = "prior";

    BOOST_REQUIRE(!fence.Probe("cuda", true, err));
    BOOST_REQUIRE_EQUAL(err, "ENGINE_ABSENT");
    BOOST_REQUIRE(!fence.installed());
    BOOST_REQUIRE(!fence.process_started());
    BOOST_REQUIRE(!fence.cuda_buffer());
    BOOST_REQUIRE(!fence.qualified());
    BOOST_REQUIRE(!fence.advertised());
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);

    err = "prior";
    BOOST_REQUIRE(!fence.Probe("VLLM", true, err));
    BOOST_REQUIRE_EQUAL(err, "ENGINE_ABSENT");

    err = "prior";
    BOOST_REQUIRE(!fence.Probe("vllm ", true, err));
    BOOST_REQUIRE_EQUAL(err, "ENGINE_ABSENT");

    err = "prior";
    BOOST_REQUIRE(!fence.Probe("", true, err));
    BOOST_REQUIRE_EQUAL(err, "ENGINE_ABSENT");
    BOOST_REQUIRE(!fence.installed());
    BOOST_REQUIRE(!fence.process_started());
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(known_present_engine_is_installed)
{
    const char* names[] = {"vllm", "sglang", "lmcache", "nixl", "mooncake", "rdma"};
    for (const char* name : names) {
        modelnet::SwarmReadFence fence;
        std::string err = "prior";

        BOOST_REQUIRE(fence.Probe(name, true, err));
        BOOST_REQUIRE(err.empty());
        BOOST_REQUIRE(fence.installed());
        BOOST_REQUIRE_EQUAL(fence.engine_name(), name);
        BOOST_REQUIRE_EQUAL(fence.engine_status(), "INSTALLED");
        BOOST_REQUIRE(!fence.qualified());
        BOOST_REQUIRE(!fence.advertised());
        BOOST_REQUIRE(!fence.process_started());
        BOOST_REQUIRE(!fence.cuda_buffer());
        BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
    }
}

BOOST_AUTO_TEST_CASE(failed_probe_does_not_clear_an_install)
{
    modelnet::SwarmReadFence fence;
    std::string err = "prior";

    BOOST_REQUIRE(fence.Probe("lmcache", true, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(fence.installed());

    err = "prior";
    BOOST_REQUIRE(!fence.Probe("lmcache", false, err));
    BOOST_REQUIRE_EQUAL(err, "ENGINE_ABSENT");
    BOOST_REQUIRE(fence.installed());
    BOOST_REQUIRE_EQUAL(fence.engine_name(), "lmcache");
    BOOST_REQUIRE_EQUAL(fence.engine_status(), "INSTALLED");
    BOOST_REQUIRE(!fence.qualified());
    BOOST_REQUIRE(!fence.advertised());
    BOOST_REQUIRE(!fence.process_started());
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);

    err = "prior";
    BOOST_REQUIRE(!fence.Probe("nccl", true, err));
    BOOST_REQUIRE_EQUAL(err, "ENGINE_ABSENT");
    BOOST_REQUIRE_EQUAL(fence.engine_name(), "lmcache");
    BOOST_REQUIRE(fence.installed());

    err = "prior";
    BOOST_REQUIRE(fence.Probe("nixl", true, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(fence.engine_name(), "nixl");
    BOOST_REQUIRE_EQUAL(fence.engine_status(), "INSTALLED");
    BOOST_REQUIRE(!fence.process_started());
    BOOST_REQUIRE(!fence.cuda_buffer());
    BOOST_REQUIRE_EQUAL(fence.bytes_moved(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
