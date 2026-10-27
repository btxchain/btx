// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_workpay/receipt.h>
#include <modelnet/swarm_workpay/workpay.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <limits>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_workpay_bind_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_receipt_or_job_stores_nothing)
{
    modelnet::SwarmWorkPay pay;
    std::string err = "prior";
    BOOST_CHECK(!pay.Bind("", "job-a", 5, err));
    BOOST_CHECK_EQUAL(err, "RECEIPT");
    BOOST_CHECK_EQUAL(pay.total(), 0);
    BOOST_CHECK(!pay.bound(""));
    BOOST_CHECK_EQUAL(pay.earned(), 0);

    err = "prior";
    BOOST_CHECK(!pay.Bind("rcpt-1", "", 5, err));
    BOOST_CHECK_EQUAL(err, "RECEIPT");
    BOOST_CHECK_EQUAL(pay.total(), 0);
    BOOST_CHECK(!pay.bound("rcpt-1"));

    err = "prior";
    BOOST_CHECK(!pay.Bind("", "", 5, err));
    BOOST_CHECK_EQUAL(err, "RECEIPT");
    BOOST_CHECK_EQUAL(pay.total(), 0);

    err = "prior";
    BOOST_REQUIRE(pay.Bind("rcpt-1", "job-a", 5, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(pay.total(), 5);
    BOOST_CHECK(pay.bound("rcpt-1"));
    BOOST_CHECK_EQUAL(pay.earned(), 0);
}

BOOST_AUTO_TEST_CASE(atoms_below_one_store_nothing)
{
    modelnet::SwarmWorkPay pay;
    std::string err = "prior";
    BOOST_CHECK(!pay.Bind("rcpt-1", "job-a", 0, err));
    BOOST_CHECK_EQUAL(err, "ATOMS");
    BOOST_CHECK_EQUAL(pay.total(), 0);
    BOOST_CHECK(!pay.bound("rcpt-1"));

    err = "prior";
    BOOST_CHECK(!pay.Bind("rcpt-1", "job-a", -3, err));
    BOOST_CHECK_EQUAL(err, "ATOMS");
    BOOST_CHECK_EQUAL(pay.total(), 0);
    BOOST_CHECK(!pay.bound("rcpt-1"));

    err = "prior";
    BOOST_CHECK(!pay.Bind("", "job-a", 0, err));
    BOOST_CHECK_EQUAL(err, "RECEIPT");
    BOOST_CHECK_EQUAL(pay.total(), 0);

    err = "prior";
    BOOST_REQUIRE(pay.Bind("rcpt-1", "job-a", 1, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(pay.total(), 1);

    err = "prior";
    BOOST_CHECK(!pay.Bind("rcpt-1", "job-a", 0, err));
    BOOST_CHECK_EQUAL(err, "ATOMS");
    BOOST_CHECK_EQUAL(pay.total(), 1);
    BOOST_CHECK(pay.bound("rcpt-1"));
}

BOOST_AUTO_TEST_CASE(first_binds_keep_job_and_sum)
{
    modelnet::SwarmWorkReceiptBook book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Bind("rcpt-1", "job-a", 8, err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(book.Bind("rcpt-2", "job-b", 3, err));
    BOOST_CHECK_EQUAL(book.total(), 11);

    std::string job = "unset";
    int64_t atoms = -1;
    BOOST_REQUIRE(book.Lookup("rcpt-1", job, atoms));
    BOOST_CHECK_EQUAL(job, "job-a");
    BOOST_CHECK_EQUAL(atoms, 8);

    err = "prior";
    BOOST_CHECK(!book.Bind("rcpt-1", "job-replaced", 20, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(book.total(), 11);
    job = "unset";
    atoms = -1;
    BOOST_REQUIRE(book.Lookup("rcpt-1", job, atoms));
    BOOST_CHECK_EQUAL(job, "job-a");
    BOOST_CHECK_EQUAL(atoms, 8);

    job = "unset";
    atoms = 4;
    BOOST_CHECK(!book.Lookup("missing", job, atoms));
    BOOST_CHECK_EQUAL(job, "unset");
    BOOST_CHECK_EQUAL(atoms, 4);
    BOOST_CHECK(!book.bound("missing"));

    err = "prior";
    BOOST_CHECK(!book.Bind("rcpt-3", "job-c", std::numeric_limits<int64_t>::max(), err));
    BOOST_CHECK_EQUAL(err, "ATOMS");
    BOOST_CHECK(!book.bound("rcpt-3"));
    BOOST_CHECK_EQUAL(book.total(), 11);
}

BOOST_AUTO_TEST_SUITE_END()
