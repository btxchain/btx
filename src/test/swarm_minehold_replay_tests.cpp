// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_minehold/codes.h>
#include <modelnet/swarm_minehold/limits.h>
#include <modelnet/swarm_minehold/swarm_minehold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_minehold_replay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(second_request_of_the_same_name_is_replay)
{
    modelnet::SwarmMineHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("mine-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmMineHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("mine-1"));
    BOOST_REQUIRE(plane.stored_name("mine-1") == "mine-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.blocks(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Request("mine-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmMineHoldReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.requested("mine-1"));
    BOOST_REQUIRE(plane.stored_name("mine-1") == "mine-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.mined() == modelnet::kSwarmMineHoldMined);
    BOOST_REQUIRE_EQUAL(plane.blocks(), 0);
    BOOST_REQUIRE(plane.blocks() == modelnet::kSwarmMineHoldBlocks);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.gpu());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("mine-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmMineHoldReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.stored_name("mine-1") == "mine-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.blocks(), 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(empty_name_is_mine_before_replay)
{
    modelnet::SwarmMineHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("mine-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmMineHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("mine-1"));
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.blocks(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Request("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmMineHoldMine);
    BOOST_REQUIRE_EQUAL(err, "MINE");
    BOOST_REQUIRE(plane.stored_name("mine-1") == "mine-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.blocks(), 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(replay_keeps_the_first_when_another_name_is_stored)
{
    modelnet::SwarmMineHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("mine-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmMineHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.blocks(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Request("mine-2", err));
    BOOST_REQUIRE(err == modelnet::kSwarmMineHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.blocks(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Request("mine-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmMineHoldReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.requested("mine-1"));
    BOOST_REQUIRE(plane.requested("mine-2"));
    BOOST_REQUIRE(plane.stored_name("mine-1") == "mine-1");
    BOOST_REQUIRE(plane.stored_name("mine-2") == "mine-2");
    BOOST_REQUIRE(plane.request_count() == 2);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.blocks(), 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmMineHoldBytesMoved);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_SUITE_END()
