// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvfabric/fabric.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_kvfabric_multiplier_tests, BasicTestingSetup)

static void ExpectNoMove(const modelnet::SwarmKvFabric& fabric, const modelnet::SwarmKvFabricResult& result)
{
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.bytes, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(fabric.bytes_moved(), false);
}

BOOST_AUTO_TEST_CASE(publish_is_held)
{
    const int64_t rates[] = {0, 1, -1, 64, static_cast<int64_t>(33554432), INT64_MAX};
    for (const int64_t rate : rates) {
        modelnet::SwarmKvFabric fabric;
        const modelnet::SwarmKvFabricResult result = fabric.Publish(rate);
        BOOST_CHECK_EQUAL(result.code, "HELD");
        BOOST_CHECK_EQUAL(result.published, false);
        BOOST_CHECK_EQUAL(fabric.published(), false);
        BOOST_CHECK_EQUAL(fabric.rate_stored(), false);
        ExpectNoMove(fabric, result);
    }
}

BOOST_AUTO_TEST_CASE(publish_stays_held_after_install)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult probe = fabric.Probe("rdma", true);
    BOOST_REQUIRE_EQUAL(probe.code, "INSTALLED");
    BOOST_CHECK_EQUAL(probe.qualified, false);
    BOOST_CHECK_EQUAL(probe.advertised, false);
    ExpectNoMove(fabric, probe);

    const modelnet::SwarmKvFabricResult result = fabric.Publish(1);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(result.published, false);
    BOOST_CHECK_EQUAL(fabric.published(), false);
    BOOST_CHECK_EQUAL(fabric.rate_stored(), false);
    BOOST_CHECK_EQUAL(fabric.engine_installed(), true);
    ExpectNoMove(fabric, result);
}

BOOST_AUTO_TEST_SUITE_END()
