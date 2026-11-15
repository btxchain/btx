// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocurrencybtx2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnocurrencybtx2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_quote_id_is_quote)
{
    modelnet::SwarmNotNoCurrencyBtx2 note;
    note.quote_id.clear();
    note.want_rename = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCurrencyBtx2Result result = modelnet::SwarmNoteNotNoCurrencyBtx2(note, err);
    BOOST_CHECK(!result.renamed);
    BOOST_CHECK_EQUAL(result.code, "QUOTE");
    BOOST_CHECK_EQUAL(err, "QUOTE");
}

BOOST_AUTO_TEST_CASE(want_rename_is_held)
{
    modelnet::SwarmNotNoCurrencyBtx2 note;
    note.quote_id = "BTX";
    note.want_rename = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoCurrencyBtx2Result result = modelnet::SwarmNoteNotNoCurrencyBtx2(note, err);
    BOOST_CHECK(!result.renamed);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoCurrencyBtx2 note;
    note.quote_id = "BTX";
    note.want_rename = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoCurrencyBtx2Result result = modelnet::SwarmNoteNotNoCurrencyBtx2(note, err);
    BOOST_CHECK(!result.renamed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
