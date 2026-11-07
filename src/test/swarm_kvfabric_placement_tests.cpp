// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvfabric/fabric.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_kvfabric_placement_tests, BasicTestingSetup)

static void ExpectNoMove(const modelnet::SwarmKvFabric& fabric, const modelnet::SwarmKvFabricResult& result)
{
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.bytes, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(fabric.bytes_moved(), false);
}

BOOST_AUTO_TEST_CASE(empty_page_stores_nothing)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult result = fabric.Place("", "fam-a");
    BOOST_CHECK_EQUAL(result.code, "PAGE");
    BOOST_CHECK(!fabric.placed(""));
    BOOST_CHECK(!fabric.placed("fam-a"));
    BOOST_CHECK(!fabric.holds_family());
    ExpectNoMove(fabric, result);
}

BOOST_AUTO_TEST_CASE(empty_family_stores_nothing)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult result = fabric.Place("page-1", "");
    BOOST_CHECK_EQUAL(result.code, "PAGE");
    BOOST_CHECK(!fabric.placed("page-1"));
    BOOST_CHECK(!fabric.holds_family());
    ExpectNoMove(fabric, result);
}

BOOST_AUTO_TEST_CASE(empty_page_and_family_store_nothing)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult result = fabric.Place("", "");
    BOOST_CHECK_EQUAL(result.code, "PAGE");
    BOOST_CHECK(!fabric.placed(""));
    BOOST_CHECK(!fabric.holds_family());
    ExpectNoMove(fabric, result);
}

BOOST_AUTO_TEST_CASE(place_stores_page_id_only)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult result = fabric.Place("page-1", "fam-a");
    BOOST_REQUIRE_EQUAL(result.code, "PLACED");
    BOOST_CHECK(fabric.placed("page-1"));
    BOOST_CHECK(!fabric.placed("fam-a"));
    BOOST_CHECK(!fabric.holds_family());
    ExpectNoMove(fabric, result);

    const modelnet::SwarmKvFabricResult again = fabric.Place("page-1", "fam-b");
    BOOST_REQUIRE_EQUAL(again.code, "PLACED");
    BOOST_CHECK(fabric.placed("page-1"));
    BOOST_CHECK(!fabric.placed("fam-b"));
    BOOST_CHECK(!fabric.holds_family());
    ExpectNoMove(fabric, again);
}

BOOST_AUTO_TEST_CASE(failed_place_does_not_block_a_later_page)
{
    modelnet::SwarmKvFabric fabric;
    const modelnet::SwarmKvFabricResult rejected = fabric.Place("page-1", "");
    BOOST_CHECK_EQUAL(rejected.code, "PAGE");
    BOOST_CHECK(!fabric.placed("page-1"));
    ExpectNoMove(fabric, rejected);

    const modelnet::SwarmKvFabricResult placed = fabric.Place("page-1", "fam-a");
    BOOST_REQUIRE_EQUAL(placed.code, "PLACED");
    BOOST_CHECK(fabric.placed("page-1"));
    BOOST_CHECK(!fabric.holds_family());
    ExpectNoMove(fabric, placed);
}

BOOST_AUTO_TEST_SUITE_END()
