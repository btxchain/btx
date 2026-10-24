// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_revenueill.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_revenueill_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_ledger_is_ledger)
{
    modelnet::SwarmRevenueIll ledger;
    ledger.want_pay = true;
    std::string err = "prior";
    const modelnet::SwarmRevenueIllResult result = modelnet::SwarmNoteRevenue(ledger, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.illustrated_a, 7000);
    BOOST_CHECK_EQUAL(result.illustrated_b, 2000);
    BOOST_CHECK_EQUAL(result.illustrated_c, 1000);
    BOOST_CHECK_EQUAL(result.code, "LEDGER");
    BOOST_CHECK_EQUAL(err, "LEDGER");
}

BOOST_AUTO_TEST_CASE(want_pay_is_held)
{
    modelnet::SwarmRevenueIll ledger;
    ledger.ledger_id = "ledger-1";
    ledger.want_pay = true;
    std::string err = "prior";
    const modelnet::SwarmRevenueIllResult result = modelnet::SwarmNoteRevenue(ledger, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.illustrated_a, 7000);
    BOOST_CHECK_EQUAL(result.illustrated_b, 2000);
    BOOST_CHECK_EQUAL(result.illustrated_c, 1000);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmRevenueIll ledger;
    ledger.ledger_id = "ledger-1";
    ledger.want_pay = false;
    std::string err = "prior";
    const modelnet::SwarmRevenueIllResult result = modelnet::SwarmNoteRevenue(ledger, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.illustrated_a, 7000);
    BOOST_CHECK_EQUAL(result.illustrated_b, 2000);
    BOOST_CHECK_EQUAL(result.illustrated_c, 1000);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
