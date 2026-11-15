// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoeleccost2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoeleccost2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_cost_id_is_cost)
{
    modelnet::SwarmNotNoElecCost2 note;
    note.want_charge = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoElecCost2Result result = modelnet::SwarmNoteNotNoElecCost2(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "COST");
    BOOST_CHECK_EQUAL(err, "COST");
}

BOOST_AUTO_TEST_CASE(want_charge_is_held)
{
    modelnet::SwarmNotNoElecCost2 note;
    note.cost_id = "cost-1";
    note.want_charge = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoElecCost2Result result = modelnet::SwarmNoteNotNoElecCost2(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoElecCost2 note;
    note.cost_id = "cost-1";
    note.want_charge = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoElecCost2Result result = modelnet::SwarmNoteNotNoElecCost2(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
