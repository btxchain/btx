// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nottax.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_nottax_tests, BasicTestingSetup)

static modelnet::SwarmNotTax NotedNote()
{
    modelnet::SwarmNotTax note;
    note.inference_id = "inference-1";
    note.open_license = false;
    note.want_tax = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_inference_id_is_inference)
{
    modelnet::SwarmNotTax note = NotedNote();
    note.inference_id.clear();
    note.open_license = true;
    note.want_tax = true;
    std::string err = "prior";
    const modelnet::SwarmNotTaxResult result = modelnet::SwarmNoteNotTax(note, err);
    BOOST_CHECK_EQUAL(result.code, "INFERENCE");
    BOOST_CHECK(!result.taxed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "INFERENCE");
}

BOOST_AUTO_TEST_CASE(open_license_without_want_tax_is_not_taxed)
{
    modelnet::SwarmNotTax note = NotedNote();
    note.open_license = true;
    note.want_tax = false;
    std::string err = "prior";
    const modelnet::SwarmNotTaxResult result = modelnet::SwarmNoteNotTax(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_TAXED");
    BOOST_CHECK(!result.taxed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "NOT_TAXED");
}

BOOST_AUTO_TEST_CASE(want_tax_without_open_license_is_not_taxed)
{
    modelnet::SwarmNotTax note = NotedNote();
    note.open_license = false;
    note.want_tax = true;
    std::string err = "prior";
    const modelnet::SwarmNotTaxResult result = modelnet::SwarmNoteNotTax(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_TAXED");
    BOOST_CHECK(!result.taxed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(err, "NOT_TAXED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotTax note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotTaxResult result = modelnet::SwarmNoteNotTax(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.taxed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
