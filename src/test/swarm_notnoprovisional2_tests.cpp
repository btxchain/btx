// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoprovisional2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoprovisional2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_receipt_id_is_receipt)
{
    std::string err = "prior";
    modelnet::SwarmNotNoProvisional2 note;
    note.provisional = true;
    note.want_book = true;
    const modelnet::SwarmNotNoProvisional2Result result = modelnet::SwarmNoteNotNoProvisional2(note, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "RECEIPT");
    BOOST_CHECK_EQUAL(err, "RECEIPT");
}

BOOST_AUTO_TEST_CASE(provisional_without_want_book_is_not_booked)
{
    std::string err = "prior";
    modelnet::SwarmNotNoProvisional2 note;
    note.receipt_id = "receipt-1";
    note.provisional = true;
    note.want_book = false;
    const modelnet::SwarmNotNoProvisional2Result result = modelnet::SwarmNoteNotNoProvisional2(note, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_BOOKED");
    BOOST_CHECK_EQUAL(err, "NOT_BOOKED");
}

BOOST_AUTO_TEST_CASE(want_book_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoProvisional2 note;
    note.receipt_id = "receipt-1";
    note.provisional = false;
    note.want_book = true;
    const modelnet::SwarmNotNoProvisional2Result result = modelnet::SwarmNoteNotNoProvisional2(note, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoProvisional2 note;
    note.receipt_id = "receipt-1";
    note.provisional = false;
    note.want_book = false;
    const modelnet::SwarmNotNoProvisional2Result result = modelnet::SwarmNoteNotNoProvisional2(note, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
