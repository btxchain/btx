// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paycycle/swarm_paycycle.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_paycycle_quote_tests, BasicTestingSetup)

namespace {

void ExpectNoSpend(const modelnet::SwarmPayCycle& cycle)
{
    BOOST_CHECK_EQUAL(cycle.atoms_moved(), 0);
    BOOST_CHECK_EQUAL(cycle.automatic_spend(), "0");
    BOOST_CHECK(!cycle.broadcast());
    BOOST_CHECK(!cycle.launched());
    BOOST_CHECK(!cycle.gpu());
    BOOST_CHECK_EQUAL(cycle.bytes_moved(), 0);
    BOOST_CHECK_EQUAL(cycle.l1_transactions(), 0);
}

} // namespace

BOOST_AUTO_TEST_CASE(empty_quote_stores_nothing)
{
    modelnet::SwarmPayCycle cycle;
    std::string err = "prior";
    BOOST_REQUIRE(cycle.Publish("chain-a", "lineage-a", "nonce-a", "application", "policy-1", err));
    const std::string id = cycle.pool_id("chain-a", "lineage-a", "nonce-a", "application", "policy-1");
    err = "prior";
    BOOST_CHECK(!cycle.Quote(id, "", err));
    BOOST_CHECK_EQUAL(err, "QUOTE");
    BOOST_CHECK(cycle.quote(id).empty());
    BOOST_CHECK_EQUAL(cycle.balance(id), 0);
    BOOST_CHECK(!cycle.funded(id));
    BOOST_CHECK(!cycle.holds_money());
    ExpectNoSpend(cycle);
}

BOOST_AUTO_TEST_CASE(fiat_is_stored_and_is_not_a_balance)
{
    modelnet::SwarmPayCycle cycle;
    std::string err = "prior";
    BOOST_REQUIRE(cycle.Publish("chain-a", "lineage-a", "nonce-a", "application", "policy-1", err));
    const std::string id = cycle.pool_id("chain-a", "lineage-a", "nonce-a", "application", "policy-1");
    BOOST_REQUIRE(cycle.Fund(id, true, err));
    BOOST_REQUIRE(cycle.Reserve(id, "txid:0", 40, err));
    BOOST_CHECK_EQUAL(cycle.balance(id), 40);

    err = "prior";
    BOOST_CHECK(!cycle.Quote(id, "12.50", err));
    BOOST_CHECK_EQUAL(err, "NOT_BALANCE");
    BOOST_CHECK_EQUAL(cycle.quote(id), "12.50");
    BOOST_CHECK_EQUAL(cycle.balance(id), 40);
    BOOST_CHECK(cycle.holds_money(id));
    ExpectNoSpend(cycle);

    err = "prior";
    BOOST_CHECK(!cycle.Quote(id, "", err));
    BOOST_CHECK_EQUAL(err, "QUOTE");
    BOOST_CHECK_EQUAL(cycle.quote(id), "12.50");
    BOOST_CHECK_EQUAL(cycle.balance(id), 40);

    err = "prior";
    BOOST_CHECK(!cycle.Quote(id, "99.00", err));
    BOOST_CHECK_EQUAL(err, "NOT_BALANCE");
    BOOST_CHECK_EQUAL(cycle.quote(id), "99.00");
    BOOST_CHECK_EQUAL(cycle.balance(id), 40);
    BOOST_CHECK_EQUAL(cycle.atoms_moved(), 0);

    err = "prior";
    BOOST_CHECK(!cycle.Quote("not-a-pool", "1.00", err));
    BOOST_CHECK_EQUAL(err, "NOT_BALANCE");
    BOOST_CHECK_EQUAL(cycle.quote("not-a-pool"), "1.00");
    BOOST_CHECK(!cycle.funded("not-a-pool"));
    BOOST_CHECK(!cycle.holds_money("not-a-pool"));
    BOOST_CHECK_EQUAL(cycle.balance("not-a-pool"), 0);
    BOOST_CHECK_EQUAL(cycle.pool_count(), 1);
    ExpectNoSpend(cycle);
}

BOOST_AUTO_TEST_SUITE_END()
