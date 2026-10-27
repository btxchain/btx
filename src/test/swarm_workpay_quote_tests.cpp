// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_workpay/fiat_quote.h>
#include <modelnet/swarm_workpay/merge.h>
#include <modelnet/swarm_workpay/workpay.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_workpay_quote_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(quote_stores_nothing_and_merge_is_not_merged)
{
    std::string err = "prior";
    BOOST_CHECK(!modelnet::SwarmWorkFiatQuote("usd", err));
    BOOST_CHECK_EQUAL(err, "NOT_BALANCE");
    err = "prior";
    BOOST_CHECK(!modelnet::SwarmWorkFiatQuote("", err));
    BOOST_CHECK_EQUAL(err, "NOT_BALANCE");
    err = "prior";
    BOOST_CHECK(!modelnet::SwarmWorkMerge(err));
    BOOST_CHECK_EQUAL(err, "NOT_MERGED");

    modelnet::SwarmWorkPay pay;
    err = "prior";
    BOOST_REQUIRE(pay.Bind("rcpt-1", "job-a", 6, err));
    BOOST_REQUIRE(pay.Bind("rcpt-2", "job-b", 7, err));
    BOOST_REQUIRE(pay.Pay("rcpt-1", false, false, err));
    BOOST_CHECK_EQUAL(pay.total(), 13);
    BOOST_CHECK_EQUAL(pay.earned(), 6);
    BOOST_CHECK(pay.paid("rcpt-1"));
    BOOST_CHECK(!pay.paid("rcpt-2"));

    err = "prior";
    BOOST_CHECK(!pay.Quote("usd", err));
    BOOST_CHECK_EQUAL(err, "NOT_BALANCE");
    BOOST_CHECK_EQUAL(pay.total(), 13);
    BOOST_CHECK_EQUAL(pay.earned(), 6);
    BOOST_CHECK(pay.bound("rcpt-1"));
    BOOST_CHECK(pay.bound("rcpt-2"));
    BOOST_CHECK(pay.paid("rcpt-1"));
    BOOST_CHECK(!pay.paid("rcpt-2"));
    BOOST_CHECK(!pay.bound("usd"));

    err = "prior";
    BOOST_CHECK(!pay.Quote("eur", err));
    BOOST_CHECK_EQUAL(err, "NOT_BALANCE");
    BOOST_CHECK_EQUAL(pay.earned(), 6);
    BOOST_CHECK_EQUAL(pay.total(), 13);

    err = "prior";
    BOOST_CHECK(!pay.Merge(err));
    BOOST_CHECK_EQUAL(err, "NOT_MERGED");
    BOOST_CHECK_EQUAL(pay.total(), 13);
    BOOST_CHECK_EQUAL(pay.earned(), 6);
    BOOST_CHECK(pay.paid("rcpt-1"));
    BOOST_CHECK(!pay.paid("rcpt-2"));
    BOOST_CHECK_EQUAL(pay.automatic_spend(), "0");
    BOOST_CHECK(!pay.Broadcast());
    BOOST_CHECK(!pay.mined());
    BOOST_CHECK_EQUAL(pay.bytes_moved(), 0);

    err = "prior";
    BOOST_REQUIRE(pay.Pay("rcpt-2", false, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(pay.earned(), 13);
    BOOST_CHECK_EQUAL(pay.bytes_moved(), 0);
    BOOST_CHECK(!pay.Broadcast());
    BOOST_CHECK(!pay.mined());
}

BOOST_AUTO_TEST_SUITE_END()
