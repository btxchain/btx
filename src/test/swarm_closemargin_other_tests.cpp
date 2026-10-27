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

BOOST_FIXTURE_TEST_SUITE(swarm_closemargin_other_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(other_block_count_is_margin_and_stores_nothing)
{
    const int64_t counts[] = {
        int64_t{0},
        int64_t{-1},
        int64_t{1},
        int64_t{159},
        int64_t{161},
        int64_t{320},
        INT64_MAX,
        INT64_MIN,
    };

    for (const int64_t blocks : counts) {
        modelnet::SwarmCloseMarginHold plane;
        std::string err = "prior";

        BOOST_REQUIRE(blocks != modelnet::kSwarmCloseMarginHoldMarginBlocks);
        BOOST_REQUIRE(!plane.Shrink(blocks, err));
        BOOST_REQUIRE(err == modelnet::kSwarmCloseMarginHoldMargin);
        BOOST_REQUIRE_EQUAL(err, "MARGIN");
        BOOST_REQUIRE(!plane.stored(blocks));
        BOOST_REQUIRE_EQUAL(plane.stored_blocks(blocks), 0);
        BOOST_REQUIRE(!plane.stored(modelnet::kSwarmCloseMarginHoldMarginBlocks));
        BOOST_REQUIRE(plane.request_count() == 0);
        BOOST_REQUIRE_EQUAL(plane.margin_blocks(), 160);
        BOOST_REQUIRE(plane.margin_blocks() == modelnet::kSwarmCloseMarginHoldMarginBlocks);
        BOOST_REQUIRE(!plane.shrunk());
        BOOST_REQUIRE(plane.shrunk() == modelnet::kSwarmCloseMarginHoldShrunk);
        BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
        BOOST_REQUIRE(!plane.gpu());
        BOOST_REQUIRE(!plane.launched());
        BOOST_REQUIRE(!plane.mined());

        err = "prior";
        BOOST_REQUIRE(!plane.Shrink(blocks, err));
        BOOST_REQUIRE(err == modelnet::kSwarmCloseMarginHoldMargin);
        BOOST_REQUIRE_EQUAL(err, "MARGIN");
        BOOST_REQUIRE(plane.request_count() == 0);
        BOOST_REQUIRE_EQUAL(plane.margin_blocks(), 160);
        BOOST_REQUIRE(!plane.shrunk());
    }
}

BOOST_AUTO_TEST_CASE(other_count_leaves_a_stored_request_in_place)
{
    modelnet::SwarmCloseMarginHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Shrink(160, err));
    BOOST_REQUIRE(err == modelnet::kSwarmCloseMarginHoldHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.stored(160));
    BOOST_REQUIRE_EQUAL(plane.stored_blocks(160), 160);
    BOOST_REQUIRE(!plane.shrunk());
    BOOST_REQUIRE_EQUAL(plane.margin_blocks(), 160);

    err = "prior";
    BOOST_REQUIRE(!plane.Shrink(159, err));
    BOOST_REQUIRE(err == modelnet::kSwarmCloseMarginHoldMargin);
    BOOST_REQUIRE_EQUAL(err, "MARGIN");
    BOOST_REQUIRE(plane.stored(160));
    BOOST_REQUIRE_EQUAL(plane.stored_blocks(160), 160);
    BOOST_REQUIRE(!plane.stored(159));
    BOOST_REQUIRE_EQUAL(plane.stored_blocks(159), 0);
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE_EQUAL(plane.margin_blocks(), 160);
    BOOST_REQUIRE(plane.margin_blocks() == modelnet::kSwarmCloseMarginHoldMarginBlocks);
    BOOST_REQUIRE(!plane.shrunk());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.mined());
}

BOOST_AUTO_TEST_SUITE_END()
