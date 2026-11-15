// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_synchold/codes.h>
#include <modelnet/swarm_synchold/limits.h>
#include <modelnet/swarm_synchold/swarm_synchold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_synchold_request_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(stored_request_stays_unsynced)
{
    modelnet::SwarmSyncHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.requested("sync-1"));
    BOOST_REQUIRE(plane.stored_name("sync-1").empty());
    BOOST_REQUIRE(plane.request_count() == 0);
    BOOST_REQUIRE(!plane.synced());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    BOOST_REQUIRE(!plane.Request("sync-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmSyncHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("sync-1"));
    BOOST_REQUIRE(plane.stored_name("sync-1") == "sync-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.synced());
    BOOST_REQUIRE(plane.synced() == modelnet::kSwarmSyncHoldSynced);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmSyncHoldBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.gpu() == modelnet::kSwarmSyncHoldGpu);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.launched() == modelnet::kSwarmSyncHoldLaunched);
}

BOOST_AUTO_TEST_CASE(a_second_distinct_name_is_stored_beside_the_first)
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
    BOOST_REQUIRE(!plane.Request("sync-2", err));
    BOOST_REQUIRE(err == modelnet::kSwarmSyncHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("sync-1"));
    BOOST_REQUIRE(plane.requested("sync-2"));
    BOOST_REQUIRE(plane.stored_name("sync-1") == "sync-1");
    BOOST_REQUIRE(plane.stored_name("sync-2") == "sync-2");
    BOOST_REQUIRE(plane.request_count() == 2);
    BOOST_REQUIRE(!plane.synced());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(space_and_code_word_are_stored_and_stay_unsynced)
{
    modelnet::SwarmSyncHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request(" ", err));
    BOOST_REQUIRE(err == modelnet::kSwarmSyncHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested(" "));
    BOOST_REQUIRE(plane.stored_name(" ") == " ");
    BOOST_REQUIRE(!plane.synced());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("SYNC", err));
    BOOST_REQUIRE(err == modelnet::kSwarmSyncHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("SYNC"));
    BOOST_REQUIRE(plane.stored_name("SYNC") == "SYNC");
    BOOST_REQUIRE(plane.requested(" "));
    BOOST_REQUIRE(plane.request_count() == 2);
    BOOST_REQUIRE(!plane.synced());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
