// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_adminhold/limits.h>
#include <modelnet/swarm_adminhold/swarm_adminhold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace {

std::vector<unsigned char> SponsorKey(unsigned char mark)
{
    return std::vector<unsigned char>(modelnet::kSwarmAdminHoldSponsorKeyBytes, mark);
}

void RequireQuiet(const modelnet::SwarmAdminHold& plane)
{
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_adminhold_bytes_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bytes_stay_zero_across_open_replay_and_moves)
{
    modelnet::SwarmAdminHold plane;
    const std::vector<unsigned char> key = SponsorKey(0x41);
    const std::vector<unsigned char> next = SponsorKey(0x42);
    std::string err = "prior";

    RequireQuiet(plane);

    BOOST_REQUIRE(!plane.Open("hold-a", 0, key, err));
    BOOST_REQUIRE_EQUAL(err, "HEIGHT");
    RequireQuiet(plane);

    BOOST_REQUIRE(!plane.Open("hold-a", 9, std::vector<unsigned char>(4, 0x01), err));
    BOOST_REQUIRE_EQUAL(err, "KEY");
    RequireQuiet(plane);

    BOOST_REQUIRE(plane.Open("hold-a", 9, key, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 9);
    BOOST_REQUIRE(plane.sponsor_key("hold-a") == key);
    RequireQuiet(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Open("hold-a", 40, next, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 9);
    BOOST_REQUIRE(plane.sponsor_key("hold-a") == key);
    RequireQuiet(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.MoveHeight("hold-a", 41, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 9);
    RequireQuiet(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.MoveKey("hold-a", next, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.sponsor_key("hold-a") == key);
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 9);
    RequireQuiet(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.MoveHeight("missing", 3, err));
    BOOST_REQUIRE_EQUAL(err, "CHANNEL");
    BOOST_REQUIRE(!plane.MoveKey("missing", next, err));
    BOOST_REQUIRE_EQUAL(err, "CHANNEL");
    BOOST_REQUIRE(plane.channel_count() == 1);
    RequireQuiet(plane);
}

BOOST_AUTO_TEST_SUITE_END()
