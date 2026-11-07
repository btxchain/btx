// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_workpay/earned.h>
#include <modelnet/swarm_workpay/workpay.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_workpay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bind_replay_does_not_add_atoms)
{
    modelnet::SwarmWorkPay pay;
    std::string err = "prior";
    BOOST_CHECK_EQUAL(pay.total(), 0);
    BOOST_CHECK_EQUAL(pay.earned(), 0);
    BOOST_CHECK(!pay.bound("rcpt-1"));

    BOOST_REQUIRE(pay.Bind("rcpt-1", "job-a", 10, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(pay.bound("rcpt-1"));
    BOOST_CHECK_EQUAL(pay.total(), 10);
    BOOST_CHECK_EQUAL(pay.earned(), 0);

    BOOST_REQUIRE(pay.Bind("rcpt-2", "job-b", 7, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(pay.total(), 17);

    err = "prior";
    BOOST_CHECK(!pay.Bind("rcpt-1", "job-other", 99, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(pay.total(), 17);
    BOOST_CHECK_EQUAL(pay.earned(), 0);
    BOOST_CHECK(pay.bound("rcpt-1"));
    BOOST_CHECK(!pay.bound("job-other"));
}

BOOST_AUTO_TEST_CASE(pay_once_then_replay)
{
    modelnet::SwarmWorkPay pay;
    std::string err = "prior";
    BOOST_REQUIRE(pay.Bind("rcpt-1", "job-a", 10, err));
    BOOST_REQUIRE(pay.Bind("rcpt-2", "job-b", 4, err));
    BOOST_CHECK_EQUAL(pay.earned(), 0);
    BOOST_CHECK(!pay.paid("rcpt-1"));

    err = "prior";
    BOOST_REQUIRE(pay.Pay("rcpt-1", false, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(pay.paid("rcpt-1"));
    BOOST_CHECK(!pay.paid("rcpt-2"));
    BOOST_CHECK_EQUAL(pay.earned(), 10);
    BOOST_CHECK_EQUAL(pay.total(), 14);

    err = "prior";
    BOOST_CHECK(!pay.Pay("rcpt-1", false, false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(pay.earned(), 10);
    BOOST_CHECK_EQUAL(pay.total(), 14);
    BOOST_CHECK(pay.paid("rcpt-1"));

    err = "prior";
    BOOST_REQUIRE(pay.Pay("rcpt-2", false, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(pay.earned(), 14);
    BOOST_CHECK_EQUAL(pay.total(), 14);
    BOOST_CHECK(pay.paid("rcpt-2"));

    err = "prior";
    BOOST_CHECK(!pay.Pay("rcpt-2", false, false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(pay.earned(), 14);
}

BOOST_AUTO_TEST_CASE(unbound_receipt_cannot_be_paid)
{
    modelnet::SwarmWorkPay pay;
    std::string err = "prior";
    BOOST_REQUIRE(pay.Bind("rcpt-1", "job-a", 6, err));

    err = "prior";
    BOOST_CHECK(!pay.Pay("missing", false, false, err));
    BOOST_CHECK_EQUAL(err, "RECEIPT");
    BOOST_CHECK_EQUAL(pay.earned(), 0);
    BOOST_CHECK_EQUAL(pay.total(), 6);
    BOOST_CHECK(!pay.paid("missing"));
    BOOST_CHECK(!pay.bound("missing"));

    err = "prior";
    BOOST_CHECK(!pay.Pay("missing", true, true, err));
    BOOST_CHECK_EQUAL(err, "RECEIPT");
    BOOST_CHECK_EQUAL(pay.earned(), 0);

    err = "prior";
    BOOST_CHECK(!pay.Pay("", false, false, err));
    BOOST_CHECK_EQUAL(err, "RECEIPT");
    BOOST_CHECK_EQUAL(pay.earned(), 0);
    BOOST_CHECK(!pay.paid("rcpt-1"));

    modelnet::SwarmWorkEarned earned;
    err = "prior";
    BOOST_CHECK(!earned.Credit("", 6, err));
    BOOST_CHECK_EQUAL(err, "RECEIPT");
    BOOST_CHECK_EQUAL(earned.earned(), 0);
    BOOST_CHECK(!earned.paid(""));

    err = "prior";
    BOOST_CHECK(!earned.Credit("rcpt-1", 0, err));
    BOOST_CHECK_EQUAL(err, "ATOMS");
    BOOST_CHECK_EQUAL(earned.earned(), 0);
    BOOST_CHECK(!earned.paid("rcpt-1"));

    err = "prior";
    BOOST_REQUIRE(earned.Credit("rcpt-1", 6, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(earned.earned(), 6);
    err = "prior";
    BOOST_CHECK(!earned.Credit("rcpt-1", 6, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(earned.earned(), 6);
}

BOOST_AUTO_TEST_SUITE_END()
