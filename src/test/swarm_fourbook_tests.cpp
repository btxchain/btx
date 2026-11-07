// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fourbook.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fourbook_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(credit_earned_and_escrow_stay_distinct)
{
    modelnet::SwarmFourBook book;
    std::string err = "prior";
    BOOST_CHECK(book.Credit("earned", 7, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.Balance("earned"), 7);

    err = "prior";
    BOOST_CHECK(book.Credit("escrow", 4, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.Balance("escrow"), 4);
    BOOST_CHECK_EQUAL(book.Balance("earned"), 7);
    BOOST_CHECK_EQUAL(book.Balance("collateral"), 0);
    BOOST_CHECK_EQUAL(book.Balance("fees"), 0);

    err = "prior";
    BOOST_CHECK(!book.Merge(err));
    BOOST_CHECK_EQUAL(err, "NOT_MERGED");
    BOOST_CHECK_EQUAL(book.Balance("earned"), 7);
    BOOST_CHECK_EQUAL(book.Balance("escrow"), 4);
    BOOST_CHECK_EQUAL(book.Balance("collateral"), 0);
    BOOST_CHECK_EQUAL(book.Balance("fees"), 0);
    BOOST_CHECK_EQUAL(book.Balance("other"), 0);
}

BOOST_AUTO_TEST_CASE(unknown_bucket_and_nonpositive_atoms_leave_balances)
{
    modelnet::SwarmFourBook book;
    std::string err;
    BOOST_CHECK(book.Credit("fees", 2, err));
    BOOST_CHECK(book.Credit("collateral", 9, err));

    err = "prior";
    BOOST_CHECK(!book.Credit("wallet", 1, err));
    BOOST_CHECK_EQUAL(err, "BUCKET");
    BOOST_CHECK_EQUAL(book.Balance("wallet"), 0);
    BOOST_CHECK_EQUAL(book.Balance("fees"), 2);
    BOOST_CHECK_EQUAL(book.Balance("collateral"), 9);

    err = "prior";
    BOOST_CHECK(!book.Credit("fees", 0, err));
    BOOST_CHECK_EQUAL(err, "ATOMS");
    BOOST_CHECK_EQUAL(book.Balance("fees"), 2);

    err = "prior";
    BOOST_CHECK(!book.Credit("earned", -3, err));
    BOOST_CHECK_EQUAL(err, "ATOMS");
    BOOST_CHECK_EQUAL(book.Balance("earned"), 0);
    BOOST_CHECK_EQUAL(book.Balance("collateral"), 9);
}

BOOST_AUTO_TEST_SUITE_END()
