// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvfabric/fabric.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_kvfabric_truncation_tests, BasicTestingSetup)

static void ExpectNoMove(const modelnet::SwarmKvFabric& fabric, const modelnet::SwarmKvFabricResult& result)
{
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.bytes, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(fabric.bytes_moved(), false);
}

BOOST_AUTO_TEST_CASE(zero_and_negative_are_truncated)
{
    modelnet::SwarmKvFabric fabric;
    const int64_t rejected[] = {0, -1, static_cast<int64_t>(-33554432)};
    for (const int64_t size : rejected) {
        const modelnet::SwarmKvFabricResult result = fabric.Accept(size);
        BOOST_CHECK_EQUAL(result.code, "TRUNCATED");
        BOOST_CHECK(!fabric.cache_accepted());
        BOOST_CHECK_EQUAL(fabric.admitted_size(), static_cast<int64_t>(0));
        BOOST_CHECK(!fabric.body_retained());
        ExpectNoMove(fabric, result);
    }
}

BOOST_AUTO_TEST_CASE(above_max_is_truncated)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult over = fabric.Accept(33554433);
    BOOST_CHECK_EQUAL(over.code, "TRUNCATED");
    BOOST_CHECK(!fabric.cache_accepted());
    BOOST_CHECK_EQUAL(fabric.admitted_size(), static_cast<int64_t>(0));
    BOOST_CHECK(!fabric.body_retained());
    ExpectNoMove(fabric, over);

    const modelnet::SwarmKvFabricResult huge = fabric.Accept(INT64_MAX);
    BOOST_CHECK_EQUAL(huge.code, "TRUNCATED");
    BOOST_CHECK(!fabric.cache_accepted());
    BOOST_CHECK_EQUAL(fabric.admitted_size(), static_cast<int64_t>(0));
    BOOST_CHECK(!fabric.body_retained());
    ExpectNoMove(fabric, huge);
}

BOOST_AUTO_TEST_CASE(size_one_and_max_are_accepted)
{
    modelnet::SwarmKvFabric one_fabric;
    const modelnet::SwarmKvFabricResult one = one_fabric.Accept(1);
    BOOST_REQUIRE_EQUAL(one.code, "ACCEPTED");
    BOOST_CHECK(one_fabric.cache_accepted());
    BOOST_CHECK_EQUAL(one_fabric.admitted_size(), static_cast<int64_t>(1));
    BOOST_CHECK(!one_fabric.body_retained());
    ExpectNoMove(one_fabric, one);

    modelnet::SwarmKvFabric max_fabric;
    const modelnet::SwarmKvFabricResult max_body = max_fabric.Accept(33554432);
    BOOST_REQUIRE_EQUAL(max_body.code, "ACCEPTED");
    BOOST_CHECK(max_fabric.cache_accepted());
    BOOST_CHECK_EQUAL(max_fabric.admitted_size(), static_cast<int64_t>(33554432));
    BOOST_CHECK(!max_fabric.body_retained());
    ExpectNoMove(max_fabric, max_body);
}

BOOST_AUTO_TEST_CASE(truncated_call_does_not_replace_an_admission)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult accepted = fabric.Accept(64);
    BOOST_REQUIRE_EQUAL(accepted.code, "ACCEPTED");
    ExpectNoMove(fabric, accepted);

    const modelnet::SwarmKvFabricResult truncated = fabric.Accept(0);
    BOOST_CHECK_EQUAL(truncated.code, "TRUNCATED");
    BOOST_CHECK(fabric.cache_accepted());
    BOOST_CHECK_EQUAL(fabric.admitted_size(), static_cast<int64_t>(64));
    BOOST_CHECK(!fabric.body_retained());
    ExpectNoMove(fabric, truncated);
}

BOOST_AUTO_TEST_SUITE_END()
