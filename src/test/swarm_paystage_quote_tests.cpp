// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paystage/fiat_quote.h>
#include <modelnet/swarm_paystage/paystage.h>
#include <modelnet/swarm_paystage/profit_split.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_paystage_quote_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(quote_stores_nothing_and_split_is_refused)
{
    std::string err = "prior";
    BOOST_CHECK(!modelnet::SwarmPayFiatQuote(err));
    BOOST_CHECK_EQUAL(err, "NOT_BALANCE");
    err = "prior";
    BOOST_CHECK(!modelnet::SwarmPayProfitSplit(err));
    BOOST_CHECK_EQUAL(err, "REFUSED");

    modelnet::SwarmPayStage stage;
    err = "prior";
    BOOST_REQUIRE(stage.Credit("escrow", 6, "e", err));
    BOOST_REQUIRE(stage.Credit("collateral", 7, "c", err));
    BOOST_REQUIRE(stage.Credit("earned", 8, "n", err));
    BOOST_REQUIRE(stage.Credit("fees", 9, "f", err));
    BOOST_REQUIRE(stage.Open("channel-1", 4, err));
    BOOST_REQUIRE(stage.Debit(1, err));

    err = "prior";
    BOOST_CHECK(!stage.Quote(err));
    BOOST_CHECK_EQUAL(err, "NOT_BALANCE");
    BOOST_CHECK_EQUAL(stage.Balance("escrow"), 6);
    BOOST_CHECK_EQUAL(stage.Balance("collateral"), 7);
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 8);
    BOOST_CHECK_EQUAL(stage.Balance("fees"), 9);
    BOOST_CHECK_EQUAL(stage.Remaining("channel-1"), 3);
    BOOST_CHECK_EQUAL(stage.Balance("usd"), -1);

    err = "prior";
    BOOST_CHECK(!stage.Split(err));
    BOOST_CHECK_EQUAL(err, "REFUSED");
    BOOST_CHECK_EQUAL(stage.Balance("escrow"), 6);
    BOOST_CHECK_EQUAL(stage.Balance("collateral"), 7);
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 8);
    BOOST_CHECK_EQUAL(stage.Balance("fees"), 9);
    BOOST_CHECK_EQUAL(stage.Remaining("channel-1"), 3);
    BOOST_CHECK_EQUAL(stage.automatic_spend(), "0");
    BOOST_CHECK(!stage.Broadcast());
    BOOST_CHECK(!stage.mined());
    BOOST_CHECK(!stage.MultiHopQualified());
}

BOOST_AUTO_TEST_SUITE_END()
