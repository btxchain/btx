// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_currencykeep.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_currencykeep_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_ledger_is_ledger)
{
    modelnet::SwarmCurrencyKeep ledger;
    ledger.want_rename = false;
    std::string err = "prior";
    const modelnet::SwarmCurrencyKeepResult result = modelnet::SwarmKeepCurrency(ledger, err);
    BOOST_CHECK(!result.renamed);
    BOOST_CHECK_EQUAL(result.currency, "BTX");
    BOOST_CHECK_EQUAL(result.code, "LEDGER");
    BOOST_CHECK_EQUAL(err, "LEDGER");
}

BOOST_AUTO_TEST_CASE(rename_request_is_held)
{
    modelnet::SwarmCurrencyKeep ledger;
    ledger.ledger_id = "main";
    ledger.want_rename = true;
    std::string err = "prior";
    const modelnet::SwarmCurrencyKeepResult result = modelnet::SwarmKeepCurrency(ledger, err);
    BOOST_CHECK(!result.renamed);
    BOOST_CHECK_EQUAL(result.currency, "BTX");
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(kept_currency_is_noted)
{
    modelnet::SwarmCurrencyKeep ledger;
    ledger.ledger_id = "main";
    ledger.want_rename = false;
    std::string err = "prior";
    const modelnet::SwarmCurrencyKeepResult result = modelnet::SwarmKeepCurrency(ledger, err);
    BOOST_CHECK(!result.renamed);
    BOOST_CHECK_EQUAL(result.currency, "BTX");
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
