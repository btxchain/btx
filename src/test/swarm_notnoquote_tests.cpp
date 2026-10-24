// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoquote.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoquote_tests, BasicTestingSetup)

static modelnet::SwarmNotNoQuote NotedNote()
{
    modelnet::SwarmNotNoQuote note;
    note.quote_id = "quote-1";
    note.want_publish = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_quote_id_is_quote)
{
    modelnet::SwarmNotNoQuote note = NotedNote();
    note.quote_id.clear();
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoQuoteResult result = modelnet::SwarmNoteNotNoQuote(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.multiplier, 0);
    BOOST_CHECK_EQUAL(result.code, "QUOTE");
    BOOST_CHECK_EQUAL(err, "QUOTE");
}

BOOST_AUTO_TEST_CASE(want_publish_is_unmeasured)
{
    modelnet::SwarmNotNoQuote note = NotedNote();
    note.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoQuoteResult result = modelnet::SwarmNoteNotNoQuote(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.multiplier, 0);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoQuote note = NotedNote();
    note.want_publish = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoQuoteResult result = modelnet::SwarmNoteNotNoQuote(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.multiplier, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
