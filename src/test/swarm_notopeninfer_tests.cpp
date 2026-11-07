// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notopeninfer.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notopeninfer_tests, BasicTestingSetup)

static modelnet::SwarmNotOpenInfer NotedNote()
{
    modelnet::SwarmNotOpenInfer note;
    note.license_id = "license-1";
    note.open_license = false;
    note.want_tax = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_license_id_is_license)
{
    modelnet::SwarmNotOpenInfer note = NotedNote();
    note.license_id.clear();
    note.open_license = true;
    note.want_tax = true;
    std::string err = "prior";
    const modelnet::SwarmNotOpenInferResult result = modelnet::SwarmNoteNotOpenInfer(note, err);
    BOOST_CHECK_EQUAL(result.code, "LICENSE");
    BOOST_CHECK(!result.taxed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "LICENSE");
}

BOOST_AUTO_TEST_CASE(open_license_without_want_tax_is_not_taxed)
{
    modelnet::SwarmNotOpenInfer note = NotedNote();
    note.open_license = true;
    note.want_tax = false;
    std::string err = "prior";
    const modelnet::SwarmNotOpenInferResult result = modelnet::SwarmNoteNotOpenInfer(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_TAXED");
    BOOST_CHECK(!result.taxed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "NOT_TAXED");
}

BOOST_AUTO_TEST_CASE(closed_license_want_tax_is_not_taxed)
{
    modelnet::SwarmNotOpenInfer note = NotedNote();
    note.open_license = false;
    note.want_tax = true;
    std::string err = "prior";
    const modelnet::SwarmNotOpenInferResult result = modelnet::SwarmNoteNotOpenInfer(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_TAXED");
    BOOST_CHECK(!result.taxed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "NOT_TAXED");
}

BOOST_AUTO_TEST_CASE(closed_license_plain_is_noted)
{
    modelnet::SwarmNotOpenInfer note = NotedNote();
    note.open_license = false;
    note.want_tax = false;
    std::string err = "prior";
    const modelnet::SwarmNotOpenInferResult result = modelnet::SwarmNoteNotOpenInfer(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.taxed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
