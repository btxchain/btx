// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodupreceipt.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnodupreceipt_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_receipt_id_is_receipt)
{
    std::string err = "prior";
    modelnet::SwarmNotNoDupReceipt note;
    note.duplicate = true;
    note.want_book = true;
    const modelnet::SwarmNotNoDupReceiptResult result = modelnet::SwarmNoteNotNoDupReceipt(note, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "RECEIPT");
    BOOST_CHECK_EQUAL(err, "RECEIPT");
}

BOOST_AUTO_TEST_CASE(duplicate_without_want_book_is_duplicate)
{
    std::string err = "prior";
    modelnet::SwarmNotNoDupReceipt note;
    note.receipt_id = "receipt-1";
    note.duplicate = true;
    note.want_book = false;
    const modelnet::SwarmNotNoDupReceiptResult result = modelnet::SwarmNoteNotNoDupReceipt(note, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "DUPLICATE");
    BOOST_CHECK_EQUAL(err, "DUPLICATE");
}

BOOST_AUTO_TEST_CASE(want_book_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoDupReceipt note;
    note.receipt_id = "receipt-1";
    note.duplicate = false;
    note.want_book = true;
    const modelnet::SwarmNotNoDupReceiptResult result = modelnet::SwarmNoteNotNoDupReceipt(note, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoDupReceipt note;
    note.receipt_id = "receipt-1";
    note.duplicate = false;
    note.want_book = false;
    const modelnet::SwarmNotNoDupReceiptResult result = modelnet::SwarmNoteNotNoDupReceipt(note, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
