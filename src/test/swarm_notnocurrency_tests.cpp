// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocurrency.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocurrency_tests, BasicTestingSetup)

static modelnet::SwarmNotNoCurrency NotedNote()
{
    modelnet::SwarmNotNoCurrency note;
    note.code_id = "BTX";
    note.want_rename = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_code_id_is_code)
{
    modelnet::SwarmNotNoCurrency note = NotedNote();
    note.code_id.clear();
    note.want_rename = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCurrencyResult result = modelnet::SwarmNoteNotNoCurrency(note, err);
    BOOST_CHECK(!result.renamed);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.code, "CODE");
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK(note.code_id.empty());
}

BOOST_AUTO_TEST_CASE(other_code_without_want_rename_is_fixed)
{
    modelnet::SwarmNotNoCurrency note = NotedNote();
    note.code_id = "other-code";
    note.want_rename = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCurrencyResult result = modelnet::SwarmNoteNotNoCurrency(note, err);
    BOOST_CHECK(!result.renamed);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.code, "FIXED");
    BOOST_CHECK_EQUAL(err, "FIXED");
    BOOST_CHECK_EQUAL(note.code_id, "other-code");
}

BOOST_AUTO_TEST_CASE(want_rename_on_btx_is_fixed)
{
    modelnet::SwarmNotNoCurrency note = NotedNote();
    note.want_rename = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCurrencyResult result = modelnet::SwarmNoteNotNoCurrency(note, err);
    BOOST_CHECK(!result.renamed);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.code, "FIXED");
    BOOST_CHECK_EQUAL(err, "FIXED");
    BOOST_CHECK_EQUAL(note.code_id, "BTX");
}

BOOST_AUTO_TEST_CASE(plain_btx_is_noted)
{
    modelnet::SwarmNotNoCurrency note = NotedNote();
    note.want_rename = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCurrencyResult result = modelnet::SwarmNoteNotNoCurrency(note, err);
    BOOST_CHECK(!result.renamed);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(note.code_id, "BTX");
}

BOOST_AUTO_TEST_SUITE_END()
