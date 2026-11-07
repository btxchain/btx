// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofee0.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnofee0_tests, BasicTestingSetup)

static modelnet::SwarmNotNoFee0 NotedNote()
{
    modelnet::SwarmNotNoFee0 note;
    note.hop_id = "hop-1";
    note.want_charge = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_hop_id_is_hop)
{
    modelnet::SwarmNotNoFee0 note = NotedNote();
    note.hop_id.clear();
    note.want_charge = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFee0Result result = modelnet::SwarmNoteNotNoFee0(note, err);
    BOOST_CHECK_EQUAL(result.code, "HOP");
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "HOP");
}

BOOST_AUTO_TEST_CASE(want_charge_is_not_charged)
{
    modelnet::SwarmNotNoFee0 note = NotedNote();
    note.want_charge = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFee0Result result = modelnet::SwarmNoteNotNoFee0(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_CHARGED");
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "NOT_CHARGED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoFee0 note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoFee0Result result = modelnet::SwarmNoteNotNoFee0(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
