// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dupreceipt/caller.h>
#include <modelnet/swarm_dupreceipt/swarm_dupreceipt.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_dupreceipt_key_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(research_key_and_scheduler_are_not_signed)
{
    std::string err = "prior";
    BOOST_REQUIRE(!modelnet::SwarmDupCaller{}.accept(true, false, err));
    BOOST_REQUIRE_EQUAL(err, "NOT_SIGNED");
    err = "prior";
    BOOST_REQUIRE(!modelnet::SwarmDupCaller{}.accept(false, true, err));
    BOOST_REQUIRE_EQUAL(err, "NOT_SIGNED");
    err = "prior";
    BOOST_REQUIRE(!modelnet::SwarmDupCaller{}.accept(true, true, err));
    BOOST_REQUIRE_EQUAL(err, "NOT_SIGNED");
    err = "prior";
    BOOST_REQUIRE(modelnet::SwarmDupCaller{}.accept(false, false, err));
}

BOOST_AUTO_TEST_CASE(research_key_refusal_leaves_the_receipt_unpaid)
{
    modelnet::SwarmDupReceipt plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Bind("research", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.bound("research"));

    err = "prior";
    BOOST_REQUIRE(!plane.Pay("research", 9, true, false, err));
    BOOST_REQUIRE_EQUAL(err, "NOT_SIGNED");
    BOOST_REQUIRE(!plane.paid("research"));
    BOOST_REQUIRE_EQUAL(plane.paid_atoms("research"), 0);
    BOOST_REQUIRE_EQUAL(plane.earned(), 0);
    BOOST_REQUIRE(plane.bound("research"));

    err = "prior";
    BOOST_REQUIRE(!plane.Pay("research", 9, true, false, err));
    BOOST_REQUIRE_EQUAL(err, "NOT_SIGNED");
    BOOST_REQUIRE(!plane.paid("research"));
    BOOST_REQUIRE_EQUAL(plane.earned(), 0);

    err = "prior";
    BOOST_REQUIRE(plane.Pay("research", 9, false, false, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.paid("research"));
    BOOST_REQUIRE_EQUAL(plane.paid_atoms("research"), 9);
    BOOST_REQUIRE_EQUAL(plane.earned(), 9);
}

BOOST_AUTO_TEST_CASE(scheduler_refusal_leaves_the_receipt_unpaid)
{
    modelnet::SwarmDupReceipt plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Bind("sched", err));
    BOOST_REQUIRE(plane.Bind("both", err));

    err = "prior";
    BOOST_REQUIRE(!plane.Pay("sched", 8, false, true, err));
    BOOST_REQUIRE_EQUAL(err, "NOT_SIGNED");
    BOOST_REQUIRE(!plane.paid("sched"));
    BOOST_REQUIRE_EQUAL(plane.earned(), 0);
    BOOST_REQUIRE(plane.bound("sched"));

    err = "prior";
    BOOST_REQUIRE(!plane.Pay("both", 3, true, true, err));
    BOOST_REQUIRE_EQUAL(err, "NOT_SIGNED");
    BOOST_REQUIRE(!plane.paid("both"));
    BOOST_REQUIRE_EQUAL(plane.earned(), 0);

    err = "prior";
    BOOST_REQUIRE(plane.Pay("sched", 8, false, false, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.paid("sched"));
    BOOST_REQUIRE_EQUAL(plane.earned(), 8);

    err = "prior";
    BOOST_REQUIRE(plane.Pay("both", 3, false, false, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.earned(), 11);
    BOOST_REQUIRE_EQUAL(plane.paid_atoms("both"), 3);
    BOOST_REQUIRE_EQUAL(plane.paid_atoms("sched"), 8);
}

BOOST_AUTO_TEST_SUITE_END()
