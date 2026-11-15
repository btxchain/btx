// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoescrow.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoescrow_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_book_id_is_book)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEscrow note;
    note.same_atoms = true;
    note.want_book = true;
    const modelnet::SwarmNotNoEscrowResult result = modelnet::SwarmNoteNotNoEscrow(note, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "BOOK");
    BOOST_CHECK_EQUAL(err, "BOOK");
}

BOOST_AUTO_TEST_CASE(same_atoms_without_want_book_is_same_atoms)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEscrow note;
    note.book_id = "book-1";
    note.same_atoms = true;
    note.want_book = false;
    const modelnet::SwarmNotNoEscrowResult result = modelnet::SwarmNoteNotNoEscrow(note, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "SAME_ATOMS");
    BOOST_CHECK_EQUAL(err, "SAME_ATOMS");
}

BOOST_AUTO_TEST_CASE(want_book_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEscrow note;
    note.book_id = "book-1";
    note.same_atoms = false;
    note.want_book = true;
    const modelnet::SwarmNotNoEscrowResult result = modelnet::SwarmNoteNotNoEscrow(note, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEscrow note;
    note.book_id = "book-1";
    note.same_atoms = false;
    note.want_book = false;
    const modelnet::SwarmNotNoEscrowResult result = modelnet::SwarmNoteNotNoEscrow(note, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
