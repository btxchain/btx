// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dupreceipt/swarm_dupreceipt.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <limits>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_dupreceipt_receipt_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_bind_stores_nothing)
{
    modelnet::SwarmDupReceipt plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Bind("", err));
    BOOST_REQUIRE_EQUAL(err, "RECEIPT");
    BOOST_REQUIRE(!plane.bound(""));
    BOOST_REQUIRE_EQUAL(plane.earned(), 0);
    BOOST_REQUIRE_EQUAL(plane.bound_count(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Bind("", err));
    BOOST_REQUIRE_EQUAL(err, "RECEIPT");
    BOOST_REQUIRE_EQUAL(plane.bound_count(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Pay("", 5, false, false, err));
    BOOST_REQUIRE_EQUAL(err, "RECEIPT");
    BOOST_REQUIRE_EQUAL(plane.earned(), 0);
    BOOST_REQUIRE(!plane.paid(""));
}

BOOST_AUTO_TEST_CASE(unknown_receipt_adds_nothing)
{
    modelnet::SwarmDupReceipt plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Bind("rcpt-1", err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Pay("missing", 5, false, false, err));
    BOOST_REQUIRE_EQUAL(err, "RECEIPT");
    BOOST_REQUIRE_EQUAL(plane.earned(), 0);
    BOOST_REQUIRE(!plane.paid("missing"));
    BOOST_REQUIRE(!plane.bound("missing"));
    BOOST_REQUIRE(!plane.paid("rcpt-1"));
    BOOST_REQUIRE_EQUAL(plane.bound_count(), 1);

    err = "prior";
    BOOST_REQUIRE(!plane.Pay("missing", 0, false, false, err));
    BOOST_REQUIRE_EQUAL(err, "RECEIPT");
    BOOST_REQUIRE_EQUAL(plane.earned(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Pay("missing", 5, true, false, err));
    BOOST_REQUIRE_EQUAL(err, "RECEIPT");
    BOOST_REQUIRE_EQUAL(plane.earned(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Pay("missing", 5, false, true, err));
    BOOST_REQUIRE_EQUAL(err, "RECEIPT");
    BOOST_REQUIRE_EQUAL(plane.earned(), 0);
}

BOOST_AUTO_TEST_CASE(atoms_below_one_add_nothing)
{
    modelnet::SwarmDupReceipt plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Bind("rcpt-1", err));
    BOOST_REQUIRE(err.empty());

    err = "prior";
    BOOST_REQUIRE(!plane.Pay("rcpt-1", 0, false, false, err));
    BOOST_REQUIRE_EQUAL(err, "ATOMS");
    BOOST_REQUIRE(!plane.paid("rcpt-1"));
    BOOST_REQUIRE_EQUAL(plane.earned(), 0);
    BOOST_REQUIRE_EQUAL(plane.paid_atoms("rcpt-1"), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Pay("rcpt-1", -3, false, false, err));
    BOOST_REQUIRE_EQUAL(err, "ATOMS");
    BOOST_REQUIRE(!plane.paid("rcpt-1"));
    BOOST_REQUIRE_EQUAL(plane.earned(), 0);

    err = "prior";
    BOOST_REQUIRE(!plane.Pay("rcpt-1", 0, true, true, err));
    BOOST_REQUIRE_EQUAL(err, "ATOMS");
    BOOST_REQUIRE(!plane.paid("rcpt-1"));

    err = "prior";
    BOOST_REQUIRE(plane.Pay("rcpt-1", 1, false, false, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.earned(), 1);
    BOOST_REQUIRE_EQUAL(plane.paid_atoms("rcpt-1"), 1);

    err = "prior";
    BOOST_REQUIRE(!plane.Pay("rcpt-1", 0, false, false, err));
    BOOST_REQUIRE_EQUAL(err, "ATOMS");
    BOOST_REQUIRE_EQUAL(plane.earned(), 1);
    BOOST_REQUIRE_EQUAL(plane.paid_atoms("rcpt-1"), 1);
}

BOOST_AUTO_TEST_CASE(overflow_leaves_the_second_receipt_unpaid)
{
    modelnet::SwarmDupReceipt plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Bind("rcpt-max", err));
    BOOST_REQUIRE(plane.Bind("rcpt-next", err));
    BOOST_REQUIRE(plane.Pay("rcpt-max", std::numeric_limits<int64_t>::max(), false, false, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.earned(), std::numeric_limits<int64_t>::max());

    err = "prior";
    BOOST_REQUIRE(!plane.Pay("rcpt-next", 1, false, false, err));
    BOOST_REQUIRE_EQUAL(err, "ATOMS");
    BOOST_REQUIRE(!plane.paid("rcpt-next"));
    BOOST_REQUIRE(plane.bound("rcpt-next"));
    BOOST_REQUIRE_EQUAL(plane.earned(), std::numeric_limits<int64_t>::max());
    BOOST_REQUIRE_EQUAL(plane.paid_atoms("rcpt-max"), std::numeric_limits<int64_t>::max());
}

BOOST_AUTO_TEST_SUITE_END()
