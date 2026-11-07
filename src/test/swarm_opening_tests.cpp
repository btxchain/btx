// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_opening.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_opening_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bind_mismatched_outpoint_stays_proposed)
{
    modelnet::SwarmOpening opening;
    std::string err;
    BOOST_CHECK(!modelnet::SwarmBindRefund(opening, false, err));
    BOOST_CHECK_EQUAL(err, "REFUND_UNBOUND");
    BOOST_CHECK(opening.state == modelnet::SwarmOpenState::Proposed);
    BOOST_CHECK(!opening.refund_bound);
    BOOST_CHECK_EQUAL(opening.automatic_spend_atoms, "0");
}

BOOST_AUTO_TEST_CASE(bind_matching_outpoint_reaches_refund_bound)
{
    modelnet::SwarmOpening opening;
    std::string err;
    BOOST_CHECK(modelnet::SwarmBindRefund(opening, true, err));
    BOOST_CHECK(opening.refund_bound);
    BOOST_CHECK(opening.state == modelnet::SwarmOpenState::RefundBound);
    BOOST_CHECK_EQUAL(opening.automatic_spend_atoms, "0");
}

BOOST_AUTO_TEST_CASE(broadcast_after_refund_bound_is_forbidden)
{
    modelnet::SwarmOpening opening;
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmBindRefund(opening, true, err));
    BOOST_CHECK(!modelnet::SwarmBroadcastFunding(opening, "funding-txid", err));
    BOOST_CHECK_EQUAL(err, "BROADCAST_FORBIDDEN");
    BOOST_CHECK(!opening.broadcast);
    BOOST_CHECK(opening.state == modelnet::SwarmOpenState::RefundBound);
    BOOST_CHECK(opening.state != modelnet::SwarmOpenState::FundingBroadcast);
    BOOST_CHECK(opening.funding_txid.empty());
    BOOST_CHECK_EQUAL(opening.automatic_spend_atoms, "0");
}

BOOST_AUTO_TEST_CASE(note_confirmations_without_broadcast)
{
    modelnet::SwarmOpening opening;
    std::string err;
    BOOST_REQUIRE(modelnet::SwarmBindRefund(opening, true, err));
    BOOST_CHECK(!modelnet::SwarmNoteConfirmations(opening, 1, err));
    BOOST_CHECK_EQUAL(err, "CONFIRMED_WITHOUT_BROADCAST");
    BOOST_CHECK_EQUAL(opening.confirmations, 0);
    BOOST_CHECK(opening.state != modelnet::SwarmOpenState::FundingConfirmed);
    BOOST_CHECK(!opening.broadcast);
    BOOST_CHECK_EQUAL(opening.automatic_spend_atoms, "0");
}

BOOST_AUTO_TEST_SUITE_END()
