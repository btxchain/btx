// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoescrowboth2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoescrowboth2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_ledger_id_is_ledger)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEscrowBoth2 note;
    note.same_atoms = true;
    note.want_book = true;
    const modelnet::SwarmNotNoEscrowBoth2Result result = modelnet::SwarmNoteNotNoEscrowBoth2(note, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "LEDGER");
    BOOST_CHECK_EQUAL(err, "LEDGER");
}

BOOST_AUTO_TEST_CASE(same_atoms_without_want_book_is_not_both)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEscrowBoth2 note;
    note.ledger_id = "ledger-1";
    note.same_atoms = true;
    note.want_book = false;
    const modelnet::SwarmNotNoEscrowBoth2Result result = modelnet::SwarmNoteNotNoEscrowBoth2(note, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_BOTH");
    BOOST_CHECK_EQUAL(err, "NOT_BOTH");
}

BOOST_AUTO_TEST_CASE(want_book_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEscrowBoth2 note;
    note.ledger_id = "ledger-1";
    note.same_atoms = false;
    note.want_book = true;
    const modelnet::SwarmNotNoEscrowBoth2Result result = modelnet::SwarmNoteNotNoEscrowBoth2(note, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEscrowBoth2 note;
    note.ledger_id = "ledger-1";
    note.same_atoms = false;
    note.want_book = false;
    const modelnet::SwarmNotNoEscrowBoth2Result result = modelnet::SwarmNoteNotNoEscrowBoth2(note, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
