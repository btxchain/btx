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
        key[i] = static_cast<unsigned char>(mark ^ static_cast<unsigned char>(i & 0xff));
    }
    return key;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_adminhold_replay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(second_open_is_replay_and_keeps_the_first_row)
{
    modelnet::SwarmAdminHold plane;
    const std::vector<unsigned char> first = SponsorKey(0x10);
    const std::vector<unsigned char> second = SponsorKey(0x80);
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("hold-a", 30, first, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 30);
    BOOST_REQUIRE(plane.sponsor_key("hold-a") == first);
    BOOST_REQUIRE(first != second);

    err = "prior";
    BOOST_REQUIRE(!plane.Open("hold-a", 99, second, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 30);
    BOOST_REQUIRE(plane.sponsor_key("hold-a") == first);
    BOOST_REQUIRE(plane.channel_count() == 1);

    err = "prior";
    BOOST_REQUIRE(!plane.Open("hold-a", 30, first, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 30);
    BOOST_REQUIRE(plane.sponsor_key("hold-a") == first);
    BOOST_REQUIRE(plane.channel_count() == 1);

    const std::vector<unsigned char> other = SponsorKey(0x33);
    err = "prior";
    BOOST_REQUIRE(plane.Open("hold-b", 4, other, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.opened("hold-b"));
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-b"), 4);
    BOOST_REQUIRE(plane.sponsor_key("hold-b") == other);
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 30);
    BOOST_REQUIRE(plane.sponsor_key("hold-a") == first);
    BOOST_REQUIRE(plane.channel_count() == 2);
}

BOOST_AUTO_TEST_CASE(replay_checks_run_after_channel_height_and_key)
{
    modelnet::SwarmAdminHold plane;
    const std::vector<unsigned char> first = SponsorKey(0x17);
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("hold-a", 6, first, err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Open("", 50, SponsorKey(0x18), err));
    BOOST_REQUIRE_EQUAL(err, "CHANNEL");
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 6);
    BOOST_REQUIRE(plane.sponsor_key("hold-a") == first);
    BOOST_REQUIRE(plane.channel_count() == 1);

    err = "prior";
    BOOST_REQUIRE(!plane.Open("hold-a", 0, SponsorKey(0x19), err));
    BOOST_REQUIRE_EQUAL(err, "HEIGHT");
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 6);
    BOOST_REQUIRE(plane.sponsor_key("hold-a") == first);

    err = "prior";
    BOOST_REQUIRE(!plane.Open("hold-a", -2, SponsorKey(0x1a), err));
    BOOST_REQUIRE_EQUAL(err, "HEIGHT");
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 6);

    err = "prior";
    const std::vector<unsigned char> short_key(modelnet::kSwarmAdminHoldSponsorKeyBytes - 1, 0x1b);
    BOOST_REQUIRE(!plane.Open("hold-a", 70, short_key, err));
    BOOST_REQUIRE_EQUAL(err, "KEY");
    BOOST_REQUIRE_EQUAL(plane.refund_height("hold-a"), 6);
    BOOST_REQUIRE(plane.sponsor_key("hold-a") == first);
    BOOST_REQUIRE(plane.channel_count() == 1);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
