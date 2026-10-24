// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocollateral2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocollateral2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_collateral_id_is_collateral)
{
    std::string err = "prior";
    modelnet::SwarmNotNoCollateral2 note;
    note.reused = true;
    note.want_book = true;
    const modelnet::SwarmNotNoCollateral2Result result = modelnet::SwarmNoteNotNoCollateral2(note, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "COLLATERAL");
    BOOST_CHECK_EQUAL(err, "COLLATERAL");
}

BOOST_AUTO_TEST_CASE(reused_without_want_book_is_same_atoms)
{
    std::string err = "prior";
    modelnet::SwarmNotNoCollateral2 note;
    note.collateral_id = "collateral-1";
    note.reused = true;
    note.want_book = false;
    const modelnet::SwarmNotNoCollateral2Result result = modelnet::SwarmNoteNotNoCollateral2(note, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "SAME_ATOMS");
    BOOST_CHECK_EQUAL(err, "SAME_ATOMS");
}

BOOST_AUTO_TEST_CASE(want_book_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoCollateral2 note;
    note.collateral_id = "collateral-1";
    note.reused = false;
    note.want_book = true;
    const modelnet::SwarmNotNoCollateral2Result result = modelnet::SwarmNoteNotNoCollateral2(note, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoCollateral2 note;
    note.collateral_id = "collateral-1";
    note.reused = false;
    note.want_book = false;
    const modelnet::SwarmNotNoCollateral2Result result = modelnet::SwarmNoteNotNoCollateral2(note, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
