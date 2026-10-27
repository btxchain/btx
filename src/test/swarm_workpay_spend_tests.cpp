// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_workpay/spend_policy.h>
#include <modelnet/swarm_workpay/workpay.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_workpay_spend_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(scheduler_and_research_key_are_not_signed)
{
    std::string err = "prior";
    BOOST_CHECK(!modelnet::SwarmWorkAcceptPay(true, false, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    err = "prior";
    BOOST_CHECK(!modelnet::SwarmWorkAcceptPay(false, true, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    err = "prior";
    BOOST_CHECK(!modelnet::SwarmWorkAcceptPay(true, true, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    err = "prior";
    BOOST_REQUIRE(modelnet::SwarmWorkAcceptPay(false, false, err));
    BOOST_CHECK(err.empty());

    modelnet::SwarmWorkPay pay;
    err = "prior";
    BOOST_REQUIRE(pay.Bind("sched", "job-s", 8, err));
    BOOST_REQUIRE(pay.Bind("research", "job-r", 9, err));
    BOOST_REQUIRE(pay.Bind("both", "job-b", 3, err));
    BOOST_CHECK_EQUAL(pay.total(), 20);

    err = "prior";
    BOOST_CHECK(!pay.Pay("sched", false, true, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK_EQUAL(pay.earned(), 0);
    BOOST_CHECK(!pay.paid("sched"));
    BOOST_CHECK(pay.bound("sched"));
    BOOST_CHECK_EQUAL(pay.total(), 20);

    err = "prior";
    BOOST_CHECK(!pay.Pay("research", true, false, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK_EQUAL(pay.earned(), 0);
    BOOST_CHECK(!pay.paid("research"));

    err = "prior";
    BOOST_CHECK(!pay.Pay("both", true, true, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK_EQUAL(pay.earned(), 0);
    BOOST_CHECK(!pay.paid("both"));

    err = "prior";
    BOOST_REQUIRE(pay.Pay("sched", false, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(pay.paid("sched"));
    BOOST_CHECK_EQUAL(pay.earned(), 8);
    BOOST_CHECK_EQUAL(pay.total(), 20);

    err = "prior";
    BOOST_REQUIRE(pay.Pay("research", false, false, err));
    BOOST_CHECK_EQUAL(pay.earned(), 17);
    BOOST_REQUIRE(pay.Pay("both", false, false, err));
    BOOST_CHECK_EQUAL(pay.earned(), 20);

    err = "prior";
    BOOST_CHECK(!pay.Pay("sched", false, false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(pay.earned(), 20);
    BOOST_CHECK_EQUAL(pay.automatic_spend(), "0");
    BOOST_CHECK(!pay.Broadcast());
    BOOST_CHECK(!pay.mined());
    BOOST_CHECK_EQUAL(pay.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(automatic_spend_stays_zero_and_broadcast_is_false)
{
    BOOST_CHECK_EQUAL(modelnet::SwarmWorkAutomaticSpend(), "0");
    BOOST_CHECK(!modelnet::SwarmWorkBroadcast());
    BOOST_CHECK(!modelnet::SwarmWorkMined());
    BOOST_CHECK_EQUAL(modelnet::SwarmWorkBytesMoved(), 0);

    modelnet::SwarmWorkPay pay;
    BOOST_CHECK_EQUAL(pay.automatic_spend(), "0");
    BOOST_CHECK(!pay.Broadcast());
    BOOST_CHECK(!pay.mined());
    BOOST_CHECK_EQUAL(pay.bytes_moved(), 0);

    std::string err;
    BOOST_REQUIRE(pay.Bind("rcpt-1", "job-a", 2, err));
    BOOST_CHECK_EQUAL(pay.automatic_spend(), "0");
    BOOST_CHECK(!pay.Broadcast());
    BOOST_CHECK(!pay.mined());
    BOOST_CHECK_EQUAL(pay.bytes_moved(), 0);

    BOOST_CHECK(!pay.Pay("rcpt-1", false, true, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK_EQUAL(pay.automatic_spend(), "0");
    BOOST_CHECK(!pay.Broadcast());
    BOOST_CHECK(!pay.mined());
    BOOST_CHECK_EQUAL(pay.bytes_moved(), 0);
    BOOST_CHECK_EQUAL(pay.earned(), 0);

    BOOST_REQUIRE(pay.Pay("rcpt-1", false, false, err));
    BOOST_CHECK_EQUAL(pay.earned(), 2);
    BOOST_CHECK_EQUAL(pay.automatic_spend(), "0");
    BOOST_CHECK(!pay.Broadcast());
    BOOST_CHECK(!pay.mined());
    BOOST_CHECK_EQUAL(pay.bytes_moved(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
