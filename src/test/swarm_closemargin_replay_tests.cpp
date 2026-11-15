// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_closemargin/codes.h>
#include <modelnet/swarm_closemargin/limits.h>
#include <modelnet/swarm_closemargin/swarm_closemarginhold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_closemargin_replay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(second_shrink_of_160_is_replay)
{
    modelnet::SwarmCloseMarginHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Shrink(160, err));
    BOOST_REQUIRE(err == modelnet::kSwarmCloseMarginHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.stored(160));
    BOOST_REQUIRE_EQUAL(plane.stored_blocks(160), 160);
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE_EQUAL(plane.margin_blocks(), 160);
    BOOST_REQUIRE(!plane.shrunk());

    err = "prior";
    BOOST_REQUIRE(!plane.Shrink(160, err));
    BOOST_REQUIRE(err == modelnet::kSwarmCloseMarginHoldReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.stored(160));
    BOOST_REQUIRE_EQUAL(plane.stored_blocks(160), 160);
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE_EQUAL(plane.margin_blocks(), 160);
    BOOST_REQUIRE(plane.margin_blocks() == modelnet::kSwarmCloseMarginHoldMarginBlocks);
    BOOST_REQUIRE(!plane.shrunk());
    BOOST_REQUIRE(plane.shrunk() == modelnet::kSwarmCloseMarginHoldShrunk);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.mined());

    err = "prior";
    BOOST_REQUIRE(!plane.Shrink(modelnet::kSwarmCloseMarginHoldMarginBlocks, err));
    BOOST_REQUIRE(err == modelnet::kSwarmCloseMarginHoldReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.stored_blocks(160), 160);
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE_EQUAL(plane.margin_blocks(), 160);
    BOOST_REQUIRE(!plane.shrunk());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(other_count_is_margin_before_replay)
{
    modelnet::SwarmCloseMarginHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Shrink(160, err));
    BOOST_REQUIRE(err == modelnet::kSwarmCloseMarginHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");

    err = "prior";
    BOOST_REQUIRE(!plane.Shrink(0, err));
    BOOST_REQUIRE(err == modelnet::kSwarmCloseMarginHoldMargin);
    BOOST_REQUIRE_EQUAL(err, "MARGIN");
    BOOST_REQUIRE_EQUAL(plane.stored_blocks(160), 160);
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE_EQUAL(plane.margin_blocks(), 160);
    BOOST_REQUIRE(!plane.shrunk());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.mined());
}

BOOST_AUTO_TEST_SUITE_END()
