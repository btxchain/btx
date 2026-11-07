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

namespace {

void RequireStill(const modelnet::SwarmCloseMarginHold& plane)
{
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

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_closemargin_quiet_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(quiet_counters_stay_fixed)
{
    modelnet::SwarmCloseMarginHold plane;
    std::string err = "prior";

    RequireStill(plane);

    BOOST_REQUIRE(!plane.Shrink(159, err));
    BOOST_REQUIRE(err == modelnet::kSwarmCloseMarginHoldMargin);
    BOOST_REQUIRE_EQUAL(err, "MARGIN");
    BOOST_REQUIRE(plane.request_count() == 0);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Shrink(160, err));
    BOOST_REQUIRE(err == modelnet::kSwarmCloseMarginHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.stored(160));
    BOOST_REQUIRE_EQUAL(plane.stored_blocks(160), 160);
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.shrunk());
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Shrink(160, err));
    BOOST_REQUIRE(err == modelnet::kSwarmCloseMarginHoldReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.stored_blocks(160), 160);
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.shrunk());
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Shrink(-1, err));
    BOOST_REQUIRE(err == modelnet::kSwarmCloseMarginHoldMargin);
    BOOST_REQUIRE_EQUAL(err, "MARGIN");
    BOOST_REQUIRE_EQUAL(plane.stored_blocks(160), 160);
    BOOST_REQUIRE(plane.request_count() == 1);
    RequireStill(plane);
}

BOOST_AUTO_TEST_SUITE_END()
