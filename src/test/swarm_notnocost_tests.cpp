// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocost.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocost_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_run_id_is_run)
{
    modelnet::SwarmNotNoCost note;
    note.unmeasured = true;
    note.want_charge = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCostResult result = modelnet::SwarmNoteNotNoCost(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "RUN");
    BOOST_CHECK_EQUAL(err, "RUN");
}

BOOST_AUTO_TEST_CASE(unmeasured_is_unmeasured_when_want_charge_is_false)
{
    modelnet::SwarmNotNoCost note;
    note.run_id = "run-1";
    note.unmeasured = true;
    note.want_charge = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCostResult result = modelnet::SwarmNoteNotNoCost(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(want_charge_is_held)
{
    modelnet::SwarmNotNoCost note;
    note.run_id = "run-1";
    note.unmeasured = false;
    note.want_charge = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCostResult result = modelnet::SwarmNoteNotNoCost(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoCost note;
    note.run_id = "run-1";
    note.unmeasured = false;
    note.want_charge = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCostResult result = modelnet::SwarmNoteNotNoCost(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
