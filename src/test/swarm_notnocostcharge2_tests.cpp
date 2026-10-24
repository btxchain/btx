// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocostcharge2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocostcharge2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_cost_id_is_cost)
{
    modelnet::SwarmNotNoCostCharge2 note;
    note.unmeasured = true;
    note.want_charge = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCostCharge2Result result = modelnet::SwarmNoteNotNoCostCharge2(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "COST");
    BOOST_CHECK_EQUAL(err, "COST");
}

BOOST_AUTO_TEST_CASE(unmeasured_is_not_charged_when_want_charge_is_false)
{
    modelnet::SwarmNotNoCostCharge2 note;
    note.cost_id = "cost-1";
    note.unmeasured = true;
    note.want_charge = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCostCharge2Result result = modelnet::SwarmNoteNotNoCostCharge2(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_CHARGED");
    BOOST_CHECK_EQUAL(err, "NOT_CHARGED");
}

BOOST_AUTO_TEST_CASE(want_charge_is_held)
{
    modelnet::SwarmNotNoCostCharge2 note;
    note.cost_id = "cost-1";
    note.unmeasured = false;
    note.want_charge = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCostCharge2Result result = modelnet::SwarmNoteNotNoCostCharge2(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoCostCharge2 note;
    note.cost_id = "cost-1";
    note.unmeasured = false;
    note.want_charge = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCostCharge2Result result = modelnet::SwarmNoteNotNoCostCharge2(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
