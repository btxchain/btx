// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_shardhold/codes.h>
#include <modelnet/swarm_shardhold/limits.h>
#include <modelnet/swarm_shardhold/swarm_shardhold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

void RequireStill(const modelnet::SwarmShardHold& plane)
{
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmShardHoldBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.gpu() == modelnet::kSwarmShardHoldGpu);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.launched() == modelnet::kSwarmShardHoldLaunched);
    BOOST_REQUIRE(!plane.sharded());
    BOOST_REQUIRE(plane.sharded() == modelnet::kSwarmShardHoldSharded);
    BOOST_REQUIRE(!plane.running());
    BOOST_REQUIRE(plane.running() == modelnet::kSwarmShardHoldRunning);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_shardhold_bytes_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bytes_stay_zero)
{
    modelnet::SwarmShardHold plane;
    std::string err = "prior";

    RequireStill(plane);

    BOOST_REQUIRE(!plane.Request("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmShardHoldShard);
    BOOST_REQUIRE_EQUAL(err, "SHARD");
    BOOST_REQUIRE(plane.request_count() == 0);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Request("shard-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmShardHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("shard-1"));
    BOOST_REQUIRE(plane.stored_name("shard-1") == "shard-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.sharded());
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Request("shard-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmShardHoldReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.stored_name("shard-1") == "shard-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.sharded());
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Request("shard-2", err));
    BOOST_REQUIRE(err == modelnet::kSwarmShardHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.stored_name("shard-2") == "shard-2");
    BOOST_REQUIRE(plane.request_count() == 2);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Request("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmShardHoldShard);
    BOOST_REQUIRE_EQUAL(err, "SHARD");
    BOOST_REQUIRE(plane.stored_name("shard-1") == "shard-1");
    BOOST_REQUIRE(plane.stored_name("shard-2") == "shard-2");
    BOOST_REQUIRE(plane.request_count() == 2);
    RequireStill(plane);
}

BOOST_AUTO_TEST_SUITE_END()
