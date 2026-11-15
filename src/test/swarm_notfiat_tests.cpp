// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfiat.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notfiat_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_quote_id_is_quote)
{
    std::string err = "prior";
    modelnet::SwarmNotFiat note;
    note.want_count = true;
    const modelnet::SwarmNotFiatResult result = modelnet::SwarmNoteNotFiat(note, err);
    BOOST_CHECK(!result.counted);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "QUOTE");
    BOOST_CHECK_EQUAL(err, "QUOTE");
}

BOOST_AUTO_TEST_CASE(want_count_is_not_balance)
{
    std::string err = "prior";
    modelnet::SwarmNotFiat note;
    note.quote_id = "quote-1";
    note.want_count = true;
    const modelnet::SwarmNotFiatResult result = modelnet::SwarmNoteNotFiat(note, err);
    BOOST_CHECK(!result.counted);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_BALANCE");
    BOOST_CHECK_EQUAL(err, "NOT_BALANCE");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotFiat note;
    note.quote_id = "quote-1";
    note.want_count = false;
    const modelnet::SwarmNotFiatResult result = modelnet::SwarmNoteNotFiat(note, err);
    BOOST_CHECK(!result.counted);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
