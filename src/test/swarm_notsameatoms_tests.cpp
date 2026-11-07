// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notsameatoms.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notsameatoms_tests, BasicTestingSetup)

static modelnet::SwarmNotSameAtoms NotedNote()
{
    modelnet::SwarmNotSameAtoms note;
    note.atom_id = "atom-1";
    note.escrow = false;
    note.collateral = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_atom_id_is_atoms)
{
    modelnet::SwarmNotSameAtoms note = NotedNote();
    note.atom_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotSameAtomsResult result = modelnet::SwarmNoteNotSameAtoms(note, err);
    BOOST_CHECK(!result.both);
    BOOST_CHECK_EQUAL(result.code, "ATOMS");
    BOOST_CHECK_EQUAL(err, "ATOMS");
}

BOOST_AUTO_TEST_CASE(escrow_and_collateral_is_reuse)
{
    modelnet::SwarmNotSameAtoms note = NotedNote();
    note.escrow = true;
    note.collateral = true;
    std::string err = "prior";
    const modelnet::SwarmNotSameAtomsResult result = modelnet::SwarmNoteNotSameAtoms(note, err);
    BOOST_CHECK(!result.both);
    BOOST_CHECK_EQUAL(result.code, "REUSE");
    BOOST_CHECK_EQUAL(err, "REUSE");
}

BOOST_AUTO_TEST_CASE(escrow_only_is_noted)
{
    modelnet::SwarmNotSameAtoms note = NotedNote();
    note.escrow = true;
    note.collateral = false;
    std::string err = "prior";
    const modelnet::SwarmNotSameAtomsResult result = modelnet::SwarmNoteNotSameAtoms(note, err);
    BOOST_CHECK(!result.both);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(collateral_only_is_noted)
{
    modelnet::SwarmNotSameAtoms note = NotedNote();
    note.escrow = false;
    note.collateral = true;
    std::string err = "prior";
    const modelnet::SwarmNotSameAtomsResult result = modelnet::SwarmNoteNotSameAtoms(note, err);
    BOOST_CHECK(!result.both);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
