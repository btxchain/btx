// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fiatquote.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fiatquote_tests, BasicTestingSetup)

static modelnet::SwarmFiatQuoteRequest NotedQuote()
{
    modelnet::SwarmFiatQuoteRequest quote;
    quote.quote_id = "q1";
    quote.currency = "BTX";
    quote.atoms = 1;
    quote.want_balance = false;
    return quote;
}

BOOST_AUTO_TEST_CASE(empty_quote_id_is_quote)
{
    modelnet::SwarmFiatQuoteRequest quote = NotedQuote();
    quote.quote_id.clear();
    std::string err = "prior";
    const modelnet::SwarmFiatQuoteResult result = modelnet::SwarmNoteFiatQuote(quote, err);
    BOOST_CHECK(!result.balance_credited);
    BOOST_CHECK_EQUAL(result.code, "QUOTE");
    BOOST_CHECK_EQUAL(err, "QUOTE");
}

BOOST_AUTO_TEST_CASE(empty_currency_is_quote)
{
    modelnet::SwarmFiatQuoteRequest quote = NotedQuote();
    quote.currency.clear();
    quote.want_balance = true;
    std::string err = "prior";
    const modelnet::SwarmFiatQuoteResult result = modelnet::SwarmNoteFiatQuote(quote, err);
    BOOST_CHECK(!result.balance_credited);
    BOOST_CHECK_EQUAL(result.code, "QUOTE");
    BOOST_CHECK_EQUAL(err, "QUOTE");
}

BOOST_AUTO_TEST_CASE(negative_atoms_are_quote)
{
    modelnet::SwarmFiatQuoteRequest quote = NotedQuote();
    quote.atoms = -1;
    quote.want_balance = true;
    std::string err = "prior";
    const modelnet::SwarmFiatQuoteResult result = modelnet::SwarmNoteFiatQuote(quote, err);
    BOOST_CHECK(!result.balance_credited);
    BOOST_CHECK_EQUAL(result.code, "QUOTE");
    BOOST_CHECK_EQUAL(err, "QUOTE");
}

BOOST_AUTO_TEST_CASE(usd_is_not_btx)
{
    modelnet::SwarmFiatQuoteRequest quote = NotedQuote();
    quote.currency = "USD";
    std::string err = "prior";
    const modelnet::SwarmFiatQuoteResult result = modelnet::SwarmNoteFiatQuote(quote, err);
    BOOST_CHECK(!result.balance_credited);
    BOOST_CHECK_EQUAL(result.code, "NOT_BTX");
    BOOST_CHECK_EQUAL(err, "NOT_BTX");
}

BOOST_AUTO_TEST_CASE(usd_want_balance_is_still_not_btx)
{
    modelnet::SwarmFiatQuoteRequest quote = NotedQuote();
    quote.currency = "USD";
    quote.want_balance = true;
    std::string err = "prior";
    const modelnet::SwarmFiatQuoteResult result = modelnet::SwarmNoteFiatQuote(quote, err);
    BOOST_CHECK(!result.balance_credited);
    BOOST_CHECK_EQUAL(result.code, "NOT_BTX");
    BOOST_CHECK_EQUAL(err, "NOT_BTX");
}

BOOST_AUTO_TEST_CASE(want_balance_is_held)
{
    modelnet::SwarmFiatQuoteRequest quote = NotedQuote();
    quote.want_balance = true;
    std::string err = "prior";
    const modelnet::SwarmFiatQuoteResult result = modelnet::SwarmNoteFiatQuote(quote, err);
    BOOST_CHECK(!result.balance_credited);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(btx_quote_is_noted)
{
    modelnet::SwarmFiatQuoteRequest quote = NotedQuote();
    std::string err = "prior";
    const modelnet::SwarmFiatQuoteResult result = modelnet::SwarmNoteFiatQuote(quote, err);
    BOOST_CHECK(!result.balance_credited);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(zero_atoms_are_noted)
{
    modelnet::SwarmFiatQuoteRequest quote = NotedQuote();
    quote.atoms = 0;
    std::string err = "prior";
    const modelnet::SwarmFiatQuoteResult result = modelnet::SwarmNoteFiatQuote(quote, err);
    BOOST_CHECK(!result.balance_credited);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
