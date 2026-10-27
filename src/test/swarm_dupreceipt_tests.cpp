// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dupreceipt/swarm_dupreceipt.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_dupreceipt_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(one_payment_adds_atoms)
{
    modelnet::SwarmDupReceipt plane;
    std::string err = "prior";

    BOOST_REQUIRE_EQUAL(plane.earned(), 0);
    BOOST_REQUIRE(!plane.bound("rcpt-1"));
    BOOST_REQUIRE(!plane.paid("rcpt-1"));
    BOOST_REQUIRE_EQUAL(plane.paid_atoms("rcpt-1"), 0);
    BOOST_REQUIRE_EQUAL(plane.bound_count(), 0);

    BOOST_REQUIRE(plane.Bind("rcpt-1", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.bound("rcpt-1"));
    BOOST_REQUIRE(!plane.paid("rcpt-1"));
    BOOST_REQUIRE_EQUAL(plane.earned(), 0);
    BOOST_REQUIRE_EQUAL(plane.bound_count(), 1);

    err = "prior";
    BOOST_REQUIRE(plane.Pay("rcpt-1", 10, false, false, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.paid("rcpt-1"));
    BOOST_REQUIRE_EQUAL(plane.paid_atoms("rcpt-1"), 10);
    BOOST_REQUIRE_EQUAL(plane.earned(), 10);

    err = "prior";
    BOOST_REQUIRE(plane.Bind("rcpt-2", err));
    BOOST_REQUIRE(err.empty());
    err = "prior";
    BOOST_REQUIRE(plane.Pay("rcpt-2", 4, false, false, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.paid("rcpt-2"));
    BOOST_REQUIRE_EQUAL(plane.paid_atoms("rcpt-2"), 4);
    BOOST_REQUIRE(plane.paid("rcpt-1"));
    BOOST_REQUIRE_EQUAL(plane.paid_atoms("rcpt-1"), 10);
    BOOST_REQUIRE_EQUAL(plane.earned(), 14);
    BOOST_REQUIRE_EQUAL(plane.bound_count(), 2);
}

BOOST_AUTO_TEST_SUITE_END()
