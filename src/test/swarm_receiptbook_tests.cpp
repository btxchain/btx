// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_receiptbook.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_receiptbook_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_receipt_id_is_receipt)
{
    modelnet::SwarmReceiptRequest receipt;
    std::string err;
    const modelnet::SwarmReceiptBookResult result = modelnet::SwarmNoteReceipt(receipt, err);
    BOOST_CHECK_EQUAL(result.booked, false);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "RECEIPT");
    BOOST_CHECK_EQUAL(err, "RECEIPT");
}

BOOST_AUTO_TEST_CASE(provisional_without_want_book)
{
    modelnet::SwarmReceiptRequest receipt;
    receipt.receipt_id = "rcpt-1";
    receipt.provisional = true;
    receipt.want_book = false;
    std::string err;
    const modelnet::SwarmReceiptBookResult result = modelnet::SwarmNoteReceipt(receipt, err);
    BOOST_CHECK_EQUAL(result.booked, false);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "PROVISIONAL");
    BOOST_CHECK_EQUAL(err, "PROVISIONAL");
}

BOOST_AUTO_TEST_CASE(want_book_without_provisional_is_held)
{
    modelnet::SwarmReceiptRequest receipt;
    receipt.receipt_id = "rcpt-1";
    receipt.provisional = false;
    receipt.want_book = true;
    std::string err;
    const modelnet::SwarmReceiptBookResult result = modelnet::SwarmNoteReceipt(receipt, err);
    BOOST_CHECK_EQUAL(result.booked, false);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted_clears_err)
{
    modelnet::SwarmReceiptRequest receipt;
    receipt.receipt_id = "rcpt-1";
    receipt.provisional = false;
    receipt.want_book = false;
    std::string err = "stale";
    const modelnet::SwarmReceiptBookResult result = modelnet::SwarmNoteReceipt(receipt, err);
    BOOST_CHECK_EQUAL(result.booked, false);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
