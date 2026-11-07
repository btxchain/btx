// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoopenlictax2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoopenlictax2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoOpenLicTax2 NotedNote()
{
    modelnet::SwarmNotNoOpenLicTax2 note;
    note.license_id = "license-1";
    note.open_local = false;
    note.want_tax = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_license_id_is_license)
{
    modelnet::SwarmNotNoOpenLicTax2 note = NotedNote();
    note.license_id.clear();
    note.open_local = true;
    note.want_tax = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoOpenLicTax2Result result = modelnet::SwarmNoteNotNoOpenLicTax2(note, err);
    BOOST_CHECK_EQUAL(result.code, "LICENSE");
    BOOST_CHECK(!result.taxed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "LICENSE");
}

BOOST_AUTO_TEST_CASE(open_local_without_want_tax_is_not_taxed)
{
    modelnet::SwarmNotNoOpenLicTax2 note = NotedNote();
    note.open_local = true;
    note.want_tax = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoOpenLicTax2Result result = modelnet::SwarmNoteNotNoOpenLicTax2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_TAXED");
    BOOST_CHECK(!result.taxed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "NOT_TAXED");
}

BOOST_AUTO_TEST_CASE(closed_local_want_tax_is_held)
{
    modelnet::SwarmNotNoOpenLicTax2 note = NotedNote();
    note.open_local = false;
    note.want_tax = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoOpenLicTax2Result result = modelnet::SwarmNoteNotNoOpenLicTax2(note, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.taxed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(closed_local_plain_is_noted)
{
    modelnet::SwarmNotNoOpenLicTax2 note = NotedNote();
    note.open_local = false;
    note.want_tax = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoOpenLicTax2Result result = modelnet::SwarmNoteNotNoOpenLicTax2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.taxed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
