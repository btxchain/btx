// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoescrow2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoescrow2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_atom_id_is_atoms)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEscrow2 note;
    note.both_roles = true;
    note.want_book = true;
    const modelnet::SwarmNotNoEscrow2Result result = modelnet::SwarmNoteNotNoEscrow2(note, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "ATOMS");
    BOOST_CHECK_EQUAL(err, "ATOMS");
}

BOOST_AUTO_TEST_CASE(both_roles_without_want_book_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEscrow2 note;
    note.atom_id = "atom-1";
    note.both_roles = true;
    note.want_book = false;
    const modelnet::SwarmNotNoEscrow2Result result = modelnet::SwarmNoteNotNoEscrow2(note, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_book_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEscrow2 note;
    note.atom_id = "atom-1";
    note.both_roles = false;
    note.want_book = true;
    const modelnet::SwarmNotNoEscrow2Result result = modelnet::SwarmNoteNotNoEscrow2(note, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEscrow2 note;
    note.atom_id = "atom-1";
    note.both_roles = false;
    note.want_book = false;
    const modelnet::SwarmNotNoEscrow2Result result = modelnet::SwarmNoteNotNoEscrow2(note, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
