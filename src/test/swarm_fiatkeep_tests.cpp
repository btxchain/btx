// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fiatkeep.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fiatkeep_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_quote)
{
    modelnet::SwarmFiatKeep quote;
    quote.quote_id.clear();
    std::string err = "stale";
    const modelnet::SwarmFiatKeepResult result = modelnet::SwarmNoteFiatQuote(quote, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "QUOTE");
    BOOST_CHECK_EQUAL(err, "QUOTE");
}

BOOST_AUTO_TEST_CASE(fiat_not_balance)
{
    modelnet::SwarmFiatKeep quote;
    quote.quote_id = "q-fiat";
    quote.fiat = true;
    quote.want_book = false;
    std::string err;
    const modelnet::SwarmFiatKeepResult result = modelnet::SwarmNoteFiatQuote(quote, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_BALANCE");
    BOOST_CHECK_EQUAL(err, "NOT_BALANCE");
}

BOOST_AUTO_TEST_CASE(want_book_held)
{
    modelnet::SwarmFiatKeep quote;
    quote.quote_id = "q-held";
    quote.fiat = false;
    quote.want_book = true;
    std::string err;
    const modelnet::SwarmFiatKeepResult result = modelnet::SwarmNoteFiatQuote(quote, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmFiatKeep quote;
    quote.quote_id = "q-noted";
    quote.fiat = false;
    quote.want_book = false;
    std::string err = "stale";
    const modelnet::SwarmFiatKeepResult result = modelnet::SwarmNoteFiatQuote(quote, err);
    BOOST_CHECK(!result.booked);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
