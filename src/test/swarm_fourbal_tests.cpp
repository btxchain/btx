// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fourbal.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fourbal_tests, BasicTestingSetup)

static modelnet::SwarmFourBal NotedLedger()
{
    modelnet::SwarmFourBal ledger;
    ledger.ledger_id = "ledger-1";
    ledger.escrow = 1;
    ledger.collateral = 2;
    ledger.earned = 3;
    ledger.spendable = 4;
    ledger.want_merge = false;
    return ledger;
}

BOOST_AUTO_TEST_CASE(empty_ledger_is_ledger)
{
    modelnet::SwarmFourBal ledger = NotedLedger();
    ledger.ledger_id.clear();
    ledger.want_merge = true;
    std::string err = "prior";
    const modelnet::SwarmFourBalResult result = modelnet::SwarmKeepFourBalances(ledger, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK_EQUAL(result.code, "LEDGER");
    BOOST_CHECK_EQUAL(err, "LEDGER");
    BOOST_CHECK_EQUAL(result.escrow, 0);
    BOOST_CHECK_EQUAL(result.collateral, 0);
    BOOST_CHECK_EQUAL(result.earned, 0);
    BOOST_CHECK_EQUAL(result.spendable, 0);
}

BOOST_AUTO_TEST_CASE(negative_escrow_is_range)
{
    modelnet::SwarmFourBal ledger = NotedLedger();
    ledger.escrow = -1;
    ledger.want_merge = true;
    std::string err = "prior";
    const modelnet::SwarmFourBalResult result = modelnet::SwarmKeepFourBalances(ledger, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK_EQUAL(result.code, "RANGE");
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK_EQUAL(result.escrow, 0);
    BOOST_CHECK_EQUAL(result.collateral, 0);
    BOOST_CHECK_EQUAL(result.earned, 0);
    BOOST_CHECK_EQUAL(result.spendable, 0);
}

BOOST_AUTO_TEST_CASE(want_merge_is_held)
{
    modelnet::SwarmFourBal ledger = NotedLedger();
    ledger.want_merge = true;
    std::string err = "prior";
    const modelnet::SwarmFourBalResult result = modelnet::SwarmKeepFourBalances(ledger, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(result.escrow, 1);
    BOOST_CHECK_EQUAL(result.collateral, 2);
    BOOST_CHECK_EQUAL(result.earned, 3);
    BOOST_CHECK_EQUAL(result.spendable, 4);
}

BOOST_AUTO_TEST_CASE(plain_record_is_noted)
{
    modelnet::SwarmFourBal ledger = NotedLedger();
    ledger.want_merge = false;
    std::string err = "prior";
    const modelnet::SwarmFourBalResult result = modelnet::SwarmKeepFourBalances(ledger, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(result.escrow, 1);
    BOOST_CHECK_EQUAL(result.collateral, 2);
    BOOST_CHECK_EQUAL(result.earned, 3);
    BOOST_CHECK_EQUAL(result.spendable, 4);
}

BOOST_AUTO_TEST_SUITE_END()
