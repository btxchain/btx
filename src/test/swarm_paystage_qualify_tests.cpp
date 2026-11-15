// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_invoice.h>
#include <modelnet/swarm_paystage/paystage.h>
#include <modelnet/swarm_paystage/qualify.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_paystage_qualify_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(qualified_aborts_and_book_stays_false)
{
    std::string err = "prior";
    BOOST_CHECK(!modelnet::SwarmPayRefuseQualified(true, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");

    err = "prior";
    BOOST_REQUIRE(modelnet::SwarmPayRefuseQualified(false, err));
    BOOST_CHECK(err.empty());

    modelnet::SwarmInvoiceBook book;
    BOOST_CHECK(!book.MultiHopQualified());
    err = "prior";
    BOOST_REQUIRE(book.Open(err));
    BOOST_CHECK(!book.MultiHopQualified());

    modelnet::SwarmPayStage stage;
    BOOST_CHECK(!stage.MultiHopQualified());
    err = "prior";
    modelnet::SwarmPaySettle pay;
    pay.invoice_id = "inv-q";
    pay.beneficiary = "ben";
    pay.objective = "objective";
    pay.liquidity_id = "liq-q";
    pay.atoms = 4;
    pay.preimage.assign(32, 0x19);
    BOOST_REQUIRE(stage.Settle(pay, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!stage.MultiHopQualified());
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 4);
    BOOST_CHECK_EQUAL(stage.Balance("escrow"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("collateral"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("fees"), 0);
    BOOST_CHECK_EQUAL(stage.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
