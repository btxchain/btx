// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotax.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnotax_tests, BasicTestingSetup)

static modelnet::SwarmNotNoTax NotedNote()
{
    modelnet::SwarmNotNoTax note;
    note.license_id = "license-1";
    note.open_license = false;
    note.want_charge = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_license_id_is_license)
{
    modelnet::SwarmNotNoTax note = NotedNote();
    note.license_id.clear();
    note.open_license = true;
    note.want_charge = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoTaxResult result = modelnet::SwarmNoteNotNoTax(note, err);
    BOOST_CHECK_EQUAL(result.code, "LICENSE");
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "LICENSE");
}

BOOST_AUTO_TEST_CASE(open_license_without_want_charge_is_not_charged)
{
    modelnet::SwarmNotNoTax note = NotedNote();
    note.open_license = true;
    note.want_charge = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoTaxResult result = modelnet::SwarmNoteNotNoTax(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_CHARGED");
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "NOT_CHARGED");
}

BOOST_AUTO_TEST_CASE(want_charge_on_closed_license_is_not_charged)
{
    modelnet::SwarmNotNoTax note = NotedNote();
    note.open_license = false;
    note.want_charge = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoTaxResult result = modelnet::SwarmNoteNotNoTax(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_CHARGED");
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "NOT_CHARGED");
}

BOOST_AUTO_TEST_CASE(plain_closed_license_is_noted)
{
    modelnet::SwarmNotNoTax note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotNoTaxResult result = modelnet::SwarmNoteNotNoTax(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
