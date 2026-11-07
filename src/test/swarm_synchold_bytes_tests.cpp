// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_synchold/codes.h>
#include <modelnet/swarm_synchold/limits.h>
#include <modelnet/swarm_synchold/swarm_synchold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

void RequireStill(const modelnet::SwarmSyncHold& plane)
{
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmSyncHoldBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.gpu() == modelnet::kSwarmSyncHoldGpu);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.launched() == modelnet::kSwarmSyncHoldLaunched);
    BOOST_REQUIRE(!plane.synced());
    BOOST_REQUIRE(plane.synced() == modelnet::kSwarmSyncHoldSynced);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_synchold_bytes_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bytes_stay_zero)
{
    modelnet::SwarmSyncHold plane;
    std::string err = "prior";

    RequireStill(plane);

    BOOST_REQUIRE(!plane.Request("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmSyncHoldSync);
    BOOST_REQUIRE_EQUAL(err, "SYNC");
    BOOST_REQUIRE(plane.request_count() == 0);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Request("sync-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmSyncHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("sync-1"));
    BOOST_REQUIRE(plane.stored_name("sync-1") == "sync-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.synced());
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Request("sync-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmSyncHoldReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.stored_name("sync-1") == "sync-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.synced());
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Request("sync-2", err));
    BOOST_REQUIRE(err == modelnet::kSwarmSyncHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.stored_name("sync-2") == "sync-2");
    BOOST_REQUIRE(plane.request_count() == 2);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Request("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmSyncHoldSync);
    BOOST_REQUIRE_EQUAL(err, "SYNC");
    BOOST_REQUIRE(plane.stored_name("sync-1") == "sync-1");
    BOOST_REQUIRE(plane.stored_name("sync-2") == "sync-2");
    BOOST_REQUIRE(plane.request_count() == 2);
    RequireStill(plane);
}

BOOST_AUTO_TEST_SUITE_END()
