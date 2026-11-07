// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcurrency.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notcurrency_tests, BasicTestingSetup)

static modelnet::SwarmNotCurrency NotedNote()
{
    modelnet::SwarmNotCurrency note;
    note.unit_id = "BTX";
    note.want_rename = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_unit_id_is_unit)
{
    modelnet::SwarmNotCurrency note = NotedNote();
    note.unit_id.clear();
    note.want_rename = true;
    std::string err = "prior";
    const modelnet::SwarmNotCurrencyResult result = modelnet::SwarmNoteNotCurrency(note, err);
    BOOST_CHECK(!result.renamed);
    BOOST_CHECK_EQUAL(result.code, "UNIT");
    BOOST_CHECK_EQUAL(err, "UNIT");
    BOOST_CHECK(note.unit_id.empty());
}

BOOST_AUTO_TEST_CASE(other_unit_without_want_rename_is_fixed)
{
    modelnet::SwarmNotCurrency note = NotedNote();
    note.unit_id = "other-unit";
    note.want_rename = false;
    std::string err = "prior";
    const modelnet::SwarmNotCurrencyResult result = modelnet::SwarmNoteNotCurrency(note, err);
    BOOST_CHECK(!result.renamed);
    BOOST_CHECK_EQUAL(result.code, "FIXED");
    BOOST_CHECK_EQUAL(err, "FIXED");
    BOOST_CHECK_EQUAL(note.unit_id, "other-unit");
}

BOOST_AUTO_TEST_CASE(want_rename_on_btx_is_fixed)
{
    modelnet::SwarmNotCurrency note = NotedNote();
    note.want_rename = true;
    std::string err = "prior";
    const modelnet::SwarmNotCurrencyResult result = modelnet::SwarmNoteNotCurrency(note, err);
    BOOST_CHECK(!result.renamed);
    BOOST_CHECK_EQUAL(result.code, "FIXED");
    BOOST_CHECK_EQUAL(err, "FIXED");
    BOOST_CHECK_EQUAL(note.unit_id, "BTX");
}

BOOST_AUTO_TEST_CASE(plain_btx_is_noted)
{
    modelnet::SwarmNotCurrency note = NotedNote();
    note.want_rename = false;
    std::string err = "prior";
    const modelnet::SwarmNotCurrencyResult result = modelnet::SwarmNoteNotCurrency(note, err);
    BOOST_CHECK(!result.renamed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(note.unit_id, "BTX");
}

BOOST_AUTO_TEST_SUITE_END()
