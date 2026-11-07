// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofee2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnofee2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoFee2 QuietNote()
{
    modelnet::SwarmNotNoFee2 note;
    note.edge_id = "edge-1";
    note.want_charge = false;
    note.base = 0;
    note.amount = 0;
    note.ppm = 0;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_edge)
{
    modelnet::SwarmNotNoFee2 note = QuietNote();
    note.edge_id.clear();
    note.want_charge = true;
    note.base = 1;
    note.amount = 1000000;
    note.ppm = 1;
    std::string err = "prior";
    const modelnet::SwarmNotNoFee2Result result = modelnet::SwarmNoteNotNoFee2(note, err);
    BOOST_CHECK_EQUAL(result.code, "EDGE");
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "EDGE");
}

BOOST_AUTO_TEST_CASE(want_charge_with_positive_base_amount_ppm)
{
    modelnet::SwarmNotNoFee2 note = QuietNote();
    note.want_charge = true;
    note.base = 1;
    note.amount = 1000000;
    note.ppm = 1;
    std::string err = "prior";
    const modelnet::SwarmNotNoFee2Result result = modelnet::SwarmNoteNotNoFee2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_CHARGED");
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "NOT_CHARGED");
}

BOOST_AUTO_TEST_CASE(quiet_note)
{
    modelnet::SwarmNotNoFee2 note = QuietNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoFee2Result result = modelnet::SwarmNoteNotNoFee2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
