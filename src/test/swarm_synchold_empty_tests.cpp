// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_synchold/codes.h>
#include <modelnet/swarm_synchold/limits.h>
#include <modelnet/swarm_synchold/swarm_synchold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_synchold_empty_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_request_is_sync_and_stores_nothing)
{
    modelnet::SwarmSyncHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmSyncHoldSync);
    BOOST_REQUIRE_EQUAL(err, "SYNC");
    BOOST_REQUIRE(!plane.requested(""));
    BOOST_REQUIRE(plane.stored_name("").empty());
    BOOST_REQUIRE(plane.request_count() == 0);
    BOOST_REQUIRE(!plane.synced());
    BOOST_REQUIRE(plane.synced() == modelnet::kSwarmSyncHoldSynced);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmSyncHoldSync);
    BOOST_REQUIRE_EQUAL(err, "SYNC");
    BOOST_REQUIRE(plane.request_count() == 0);
    BOOST_REQUIRE(!plane.synced());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(empty_name_leaves_a_stored_request_in_place)
{
    modelnet::SwarmSyncHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("sync-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmSyncHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("sync-1"));
    BOOST_REQUIRE(plane.stored_name("sync-1") == "sync-1");
    BOOST_REQUIRE(!plane.synced());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmSyncHoldSync);
    BOOST_REQUIRE_EQUAL(err, "SYNC");
    BOOST_REQUIRE(plane.requested("sync-1"));
    BOOST_REQUIRE(plane.stored_name("sync-1") == "sync-1");
    BOOST_REQUIRE(!plane.requested(""));
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.synced());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
