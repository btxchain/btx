// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosame.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnosame_tests, BasicTestingSetup)

static modelnet::SwarmNotNoSame NotedNote()
{
    modelnet::SwarmNotNoSame note;
    note.atom_id = "atom-1";
    note.escrow = false;
    note.collateral = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_atom_id_is_atom)
{
    modelnet::SwarmNotNoSame note = NotedNote();
    note.atom_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotNoSameResult result = modelnet::SwarmNoteNotNoSame(note, err);
    BOOST_CHECK(!result.counted_twice);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "ATOM");
    BOOST_CHECK_EQUAL(err, "ATOM");
}

BOOST_AUTO_TEST_CASE(escrow_and_collateral_is_same_atoms)
{
    modelnet::SwarmNotNoSame note = NotedNote();
    note.escrow = true;
    note.collateral = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSameResult result = modelnet::SwarmNoteNotNoSame(note, err);
    BOOST_CHECK(!result.counted_twice);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "SAME_ATOMS");
    BOOST_CHECK_EQUAL(err, "SAME_ATOMS");
}

BOOST_AUTO_TEST_CASE(escrow_only_is_noted)
{
    modelnet::SwarmNotNoSame note = NotedNote();
    note.escrow = true;
    note.collateral = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSameResult result = modelnet::SwarmNoteNotNoSame(note, err);
    BOOST_CHECK(!result.counted_twice);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(collateral_only_is_noted)
{
    modelnet::SwarmNotNoSame note = NotedNote();
    note.escrow = false;
    note.collateral = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSameResult result = modelnet::SwarmNoteNotNoSame(note, err);
    BOOST_CHECK(!result.counted_twice);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
