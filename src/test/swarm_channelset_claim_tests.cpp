// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_channelset/channelset.h>
#include <modelnet/swarm_paymesh.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_channelset_claim_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(claim_allowed_returns_claim_before_refund)
{
    modelnet::SwarmChannelSet plane;
    const int height = 100;
    const int refund_closed = height + 160;
    const int refund_open = height + 161;

    BOOST_REQUIRE(plane.ClaimAllowed(height, refund_open) == modelnet::SwarmClaimBeforeRefund(height, refund_open));
    BOOST_REQUIRE(plane.ClaimAllowed(height, refund_closed) == modelnet::SwarmClaimBeforeRefund(height, refund_closed));
    BOOST_REQUIRE(plane.ClaimAllowed(height, height) == modelnet::SwarmClaimBeforeRefund(height, height));
    BOOST_REQUIRE(plane.ClaimAllowed(height, refund_open));
    BOOST_REQUIRE(!plane.ClaimAllowed(height, refund_closed));
    BOOST_REQUIRE(!plane.ClaimAllowed(height, height));
    BOOST_REQUIRE(!plane.ClaimAllowed(1000, 1000));

    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(!plane.mined());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(!plane.funded());
    BOOST_REQUIRE(!plane.refund_built());
    BOOST_REQUIRE(plane.cumulative() == 0);
    BOOST_REQUIRE(plane.payout_outputs() == 0);
    BOOST_REQUIRE(!plane.multi_hop_qualified());
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
