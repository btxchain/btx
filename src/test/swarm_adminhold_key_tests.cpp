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
    return std::vector<unsigned char>(size, mark);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_adminhold_key_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(short_key_is_refused_and_stores_nothing)
{
    modelnet::SwarmAdminHold plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Open("hold-a", 12, SponsorKey(0, 0x01), err));
    BOOST_REQUIRE_EQUAL(err, "KEY");
    BOOST_REQUIRE(!plane.opened("hold-a"));
    BOOST_REQUIRE(plane.channel_count() == 0);
    BOOST_REQUIRE(plane.sponsor_key("hold-a").empty());
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Open("hold-a", 12, SponsorKey(32, 0x02), err));
    BOOST_REQUIRE_EQUAL(err, "KEY");
    BOOST_REQUIRE(plane.channel_count() == 0);

    err = "prior";
    const std::size_t short_len = modelnet::kSwarmAdminHoldSponsorKeyBytes - 1;
    BOOST_REQUIRE(!plane.Open("hold-a", 12, SponsorKey(short_len, 0x03), err));
    BOOST_REQUIRE_EQUAL(err, "KEY");
    BOOST_REQUIRE(!plane.opened("hold-a"));
    BOOST_REQUIRE(plane.channel_count() == 0);

    err = "prior";
    const std::size_t long_len = modelnet::kSwarmAdminHoldSponsorKeyBytes + 1;
    BOOST_REQUIRE(!plane.Open("hold-a", 12, SponsorKey(long_len, 0x04), err));
    BOOST_REQUIRE_EQUAL(err, "KEY");
    BOOST_REQUIRE(!plane.opened("hold-a"));
    BOOST_REQUIRE(plane.sponsor_key("hold-a").empty());
    BOOST_REQUIRE(plane.channel_count() == 0);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");

    const std::vector<unsigned char> key = SponsorKey(modelnet::kSwarmAdminHoldSponsorKeyBytes, 0x05);
    err = "prior";
    BOOST_REQUIRE(plane.Open("hold-a", 12, key, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.opened("hold-a"));
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 12);
    BOOST_REQUIRE(plane.sponsor_key("hold-a") == key);
    BOOST_REQUIRE(plane.channel_count() == 1);

    err = "prior";
    BOOST_REQUIRE(!plane.Open("hold-b", 12, SponsorKey(1, 0x06), err));
    BOOST_REQUIRE_EQUAL(err, "KEY");
    BOOST_REQUIRE(!plane.opened("hold-b"));
    BOOST_REQUIRE(plane.sponsor_key("hold-a") == key);
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 12);
    BOOST_REQUIRE(plane.channel_count() == 1);
}

BOOST_AUTO_TEST_SUITE_END()
