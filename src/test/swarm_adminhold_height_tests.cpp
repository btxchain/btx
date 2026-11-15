// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_adminhold/limits.h>
#include <modelnet/swarm_adminhold/swarm_adminhold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <string>
#include <vector>

namespace {

std::vector<unsigned char> SponsorKey(unsigned char mark)
{
    std::vector<unsigned char> key(modelnet::kSwarmAdminHoldSponsorKeyBytes);
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<unsigned char>(static_cast<unsigned char>(i) ^ mark);
    }
    return key;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_adminhold_height_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(height_move_on_unknown_channel_is_channel)
{
    modelnet::SwarmAdminHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.MoveHeight("hold-a", 40, err));
    BOOST_REQUIRE_EQUAL(err, "CHANNEL");
    BOOST_REQUIRE(!plane.opened("hold-a"));
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 0);
    BOOST_REQUIRE(plane.channel_count() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.MoveHeight("", 40, err));
    BOOST_REQUIRE_EQUAL(err, "CHANNEL");
    BOOST_REQUIRE(plane.channel_count() == 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
}

BOOST_AUTO_TEST_CASE(height_move_is_held_and_leaves_the_stored_height)
{
    modelnet::SwarmAdminHold plane;
    const std::vector<unsigned char> key = SponsorKey(0x3c);
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("hold-a", 15, key, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 15);
    BOOST_REQUIRE(plane.sponsor_key("hold-a") == key);

    err = "prior";
    BOOST_REQUIRE(!plane.MoveHeight("hold-a", 16, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 15);
    BOOST_REQUIRE(plane.sponsor_key("hold-a") == key);
    BOOST_REQUIRE(plane.channel_count() == 1);

    err = "prior";
    BOOST_REQUIRE(!plane.MoveHeight("hold-a", 15, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 15);

    err = "prior";
    BOOST_REQUIRE(!plane.MoveHeight("hold-a", 0, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 15);

    err = "prior";
    BOOST_REQUIRE(!plane.MoveHeight("hold-a", -9, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 15);
    BOOST_REQUIRE(plane.sponsor_key("hold-a") == key);

    err = "prior";
    BOOST_REQUIRE(!plane.MoveHeight("hold-b", 90, err));
    BOOST_REQUIRE_EQUAL(err, "CHANNEL");
    BOOST_REQUIRE(!plane.opened("hold-b"));
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 15);
    BOOST_REQUIRE(plane.sponsor_key("hold-a") == key);
    BOOST_REQUIRE(plane.channel_count() == 1);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
