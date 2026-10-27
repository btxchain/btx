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
        key[i] = static_cast<unsigned char>(mark + static_cast<unsigned char>(i & 0xff));
    }
    return key;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_adminhold_open_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_and_low_height_store_nothing)
{
    modelnet::SwarmAdminHold plane;
    const std::vector<unsigned char> key = SponsorKey(0x11);
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Open("", 8, key, err));
    BOOST_REQUIRE_EQUAL(err, "CHANNEL");
    BOOST_REQUIRE(!plane.opened(""));
    BOOST_REQUIRE(plane.channel_count() == 0);
    BOOST_REQUIRE(plane.sponsor_key("").empty());
    BOOST_REQUIRE_EQUAL(plane.refund_height(""), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Open("hold-a", 0, key, err));
    BOOST_REQUIRE_EQUAL(err, "HEIGHT");
    BOOST_REQUIRE(!plane.opened("hold-a"));
    BOOST_REQUIRE(plane.channel_count() == 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Open("hold-a", -4, key, err));
    BOOST_REQUIRE_EQUAL(err, "HEIGHT");
    BOOST_REQUIRE(!plane.opened("hold-a"));
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 0);
    BOOST_REQUIRE(plane.sponsor_key("hold-a").empty());
    BOOST_REQUIRE(plane.channel_count() == 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(successful_open_stores_height_and_key)
{
    modelnet::SwarmAdminHold plane;
    const std::vector<unsigned char> key = SponsorKey(0x21);
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("hold-a", 8, key, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.opened("hold-a"));
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 8);
    BOOST_REQUIRE(plane.sponsor_key("hold-a") == key);
    BOOST_REQUIRE(plane.channel_count() == 1);
    BOOST_REQUIRE(!plane.opened("hold-b"));

    const std::vector<unsigned char> other = SponsorKey(0x44);
    err = "prior";
    BOOST_REQUIRE(plane.Open("hold-b", 1, other, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.opened("hold-b"));
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-b"), 1);
    BOOST_REQUIRE(plane.sponsor_key("hold-b") == other);
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 8);
    BOOST_REQUIRE(plane.sponsor_key("hold-a") == key);
    BOOST_REQUIRE(plane.channel_count() == 2);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
