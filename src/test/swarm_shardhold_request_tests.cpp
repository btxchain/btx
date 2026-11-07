// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_shardhold/codes.h>
#include <modelnet/swarm_shardhold/limits.h>
#include <modelnet/swarm_shardhold/swarm_shardhold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_shardhold_request_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(stored_request_stays_unsharded)
{
    modelnet::SwarmShardHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.requested("shard-1"));
    BOOST_REQUIRE(plane.stored_name("shard-1").empty());
    BOOST_REQUIRE(plane.request_count() == 0);
    BOOST_REQUIRE(!plane.sharded());
    BOOST_REQUIRE(!plane.running());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    BOOST_REQUIRE(!plane.Request("shard-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmShardHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("shard-1"));
    BOOST_REQUIRE(plane.stored_name("shard-1") == "shard-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.sharded());
    BOOST_REQUIRE(plane.sharded() == modelnet::kSwarmShardHoldSharded);
    BOOST_REQUIRE(!plane.running());
    BOOST_REQUIRE(plane.running() == modelnet::kSwarmShardHoldRunning);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmShardHoldBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.gpu() == modelnet::kSwarmShardHoldGpu);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.launched() == modelnet::kSwarmShardHoldLaunched);
}

BOOST_AUTO_TEST_CASE(a_second_distinct_name_is_stored_beside_the_first)
{
    modelnet::SwarmShardHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("shard-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmShardHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("shard-1"));
    BOOST_REQUIRE(plane.stored_name("shard-1") == "shard-1");

    err = "prior";
    BOOST_REQUIRE(!plane.Request("shard-2", err));
    BOOST_REQUIRE(err == modelnet::kSwarmShardHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("shard-1"));
    BOOST_REQUIRE(plane.requested("shard-2"));
    BOOST_REQUIRE(plane.stored_name("shard-1") == "shard-1");
    BOOST_REQUIRE(plane.stored_name("shard-2") == "shard-2");
    BOOST_REQUIRE(plane.request_count() == 2);
    BOOST_REQUIRE(!plane.sharded());
    BOOST_REQUIRE(!plane.running());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(space_and_code_word_are_stored_and_stay_unsharded)
{
    modelnet::SwarmShardHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request(" ", err));
    BOOST_REQUIRE(err == modelnet::kSwarmShardHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested(" "));
    BOOST_REQUIRE(plane.stored_name(" ") == " ");
    BOOST_REQUIRE(!plane.sharded());
    BOOST_REQUIRE(!plane.running());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("SHARD", err));
    BOOST_REQUIRE(err == modelnet::kSwarmShardHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("SHARD"));
    BOOST_REQUIRE(plane.stored_name("SHARD") == "SHARD");
    BOOST_REQUIRE(plane.requested(" "));
    BOOST_REQUIRE(plane.request_count() == 2);
    BOOST_REQUIRE(!plane.sharded());
    BOOST_REQUIRE(!plane.running());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
