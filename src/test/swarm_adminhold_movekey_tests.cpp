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

std::vector<unsigned char> SponsorKey(std::size_t size, unsigned char mark)
{
    std::vector<unsigned char> key(size);
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<unsigned char>(mark + static_cast<unsigned char>(i & 0x0f));
    }
    return key;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_adminhold_movekey_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(key_move_on_unknown_channel_is_channel)
{
    modelnet::SwarmAdminHold plane;
    const std::vector<unsigned char> next = SponsorKey(modelnet::kSwarmAdminHoldSponsorKeyBytes, 0x70);
    std::string err = "prior";

    BOOST_REQUIRE(!plane.MoveKey("hold-a", next, err));
    BOOST_REQUIRE_EQUAL(err, "CHANNEL");
    BOOST_REQUIRE(!plane.opened("hold-a"));
    BOOST_REQUIRE(plane.sponsor_key("hold-a").empty());
    BOOST_REQUIRE(plane.channel_count() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.MoveKey("", next, err));
    BOOST_REQUIRE_EQUAL(err, "CHANNEL");
    BOOST_REQUIRE(plane.channel_count() == 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(key_move_is_held_and_leaves_the_stored_key)
{
    modelnet::SwarmAdminHold plane;
    const std::vector<unsigned char> key = SponsorKey(modelnet::kSwarmAdminHoldSponsorKeyBytes, 0x2a);
    const std::vector<unsigned char> next = SponsorKey(modelnet::kSwarmAdminHoldSponsorKeyBytes, 0x5b);
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("hold-a", 22, key, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.sponsor_key("hold-a") == key);
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 22);
    BOOST_REQUIRE(key != next);

    err = "prior";
    BOOST_REQUIRE(!plane.MoveKey("hold-a", next, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.sponsor_key("hold-a") == key);
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 22);
    BOOST_REQUIRE(plane.channel_count() == 1);

    err = "prior";
    BOOST_REQUIRE(!plane.MoveKey("hold-a", key, err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.sponsor_key("hold-a") == key);

    err = "prior";
    BOOST_REQUIRE(!plane.MoveKey("hold-a", SponsorKey(0, 0x01), err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.sponsor_key("hold-a") == key);
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 22);

    err = "prior";
    BOOST_REQUIRE(!plane.MoveKey("hold-a", SponsorKey(modelnet::kSwarmAdminHoldSponsorKeyBytes - 1, 0x09), err));
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.sponsor_key("hold-a") == key);

    err = "prior";
    BOOST_REQUIRE(!plane.MoveKey("hold-b", next, err));
    BOOST_REQUIRE_EQUAL(err, "CHANNEL");
    BOOST_REQUIRE(!plane.opened("hold-b"));
    BOOST_REQUIRE(plane.sponsor_key("hold-a") == key);
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 22);
    BOOST_REQUIRE(plane.channel_count() == 1);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
