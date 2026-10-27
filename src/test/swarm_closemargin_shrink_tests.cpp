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

BOOST_FIXTURE_TEST_SUITE(swarm_closemargin_shrink_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(stored_shrink_stays_unshrunk)
{
    modelnet::SwarmCloseMarginHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.stored(160));
    BOOST_REQUIRE_EQUAL(plane.stored_blocks(160), 0);
    BOOST_REQUIRE(plane.request_count() == 0);
    BOOST_REQUIRE_EQUAL(plane.margin_blocks(), 160);
    BOOST_REQUIRE(plane.margin_blocks() == modelnet::kSwarmCloseMarginHoldMarginBlocks);
    BOOST_REQUIRE(!plane.shrunk());
    BOOST_REQUIRE(plane.shrunk() == modelnet::kSwarmCloseMarginHoldShrunk);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmCloseMarginHoldBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.gpu() == modelnet::kSwarmCloseMarginHoldGpu);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.launched() == modelnet::kSwarmCloseMarginHoldLaunched);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.mined() == modelnet::kSwarmCloseMarginHoldMined);

    BOOST_REQUIRE(!plane.Shrink(modelnet::kSwarmCloseMarginHoldMarginBlocks, err));
    BOOST_REQUIRE(err == modelnet::kSwarmCloseMarginHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.stored(160));
    BOOST_REQUIRE_EQUAL(plane.stored_blocks(160), 160);
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE_EQUAL(plane.margin_blocks(), 160);
    BOOST_REQUIRE(plane.margin_blocks() == modelnet::kSwarmCloseMarginHoldMarginBlocks);
    BOOST_REQUIRE(!plane.shrunk());
    BOOST_REQUIRE(plane.shrunk() == modelnet::kSwarmCloseMarginHoldShrunk);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmCloseMarginHoldBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.gpu() == modelnet::kSwarmCloseMarginHoldGpu);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.launched() == modelnet::kSwarmCloseMarginHoldLaunched);
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.mined() == modelnet::kSwarmCloseMarginHoldMined);
}

BOOST_AUTO_TEST_SUITE_END()
