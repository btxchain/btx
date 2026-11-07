// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_channelset/channelset.h>
#include <pqkey.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace {

std::vector<unsigned char> Pubkey(unsigned char fill)
{
    return std::vector<unsigned char>(MLDSA44_PUBKEY_SIZE, fill);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_channelset_policy_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(flags_stay_closed_on_an_empty_plane)
{
    modelnet::SwarmChannelSet plane;
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.multi_hop_qualified());
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
    BOOST_REQUIRE(!plane.funded());
    BOOST_REQUIRE(!plane.refund_built());
}

BOOST_AUTO_TEST_CASE(flags_stay_closed_across_settlement)
{
    modelnet::SwarmChannelSet plane;
    std::string err;
    BOOST_REQUIRE(plane.Open("lane", 1000, Pubkey(0x51), Pubkey(0x52), err));
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
    BOOST_REQUIRE(!plane.broadcast());

    BOOST_REQUIRE(plane.Refund(1000, err));
    BOOST_REQUIRE(plane.refund_built());
    BOOST_REQUIRE(plane.refund_value() == 1000);
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);

    BOOST_REQUIRE(plane.Fund(err));
    BOOST_REQUIRE(plane.funded());
    BOOST_REQUIRE(!plane.broadcast());

    BOOST_REQUIRE(plane.Payout(40, 100, 1000, err));
    BOOST_REQUIRE(plane.cumulative() == 40);
    BOOST_REQUIRE(plane.payout_worker_value() == 40);
    BOOST_REQUIRE(plane.payout_sponsor_value() == 960);
    BOOST_REQUIRE(plane.payout_outputs() == 2);
    BOOST_REQUIRE(plane.ClaimAllowed(100, 1000));
    BOOST_REQUIRE(!plane.ClaimAllowed(840, 1000));

    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.multi_hop_qualified());
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
    BOOST_REQUIRE(plane.refund_built());
    BOOST_REQUIRE(plane.funded());
}

BOOST_AUTO_TEST_SUITE_END()
