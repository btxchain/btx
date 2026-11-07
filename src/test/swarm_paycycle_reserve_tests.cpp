// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paycycle/codes.h>
#include <modelnet/swarm_paycycle/swarm_paycycle.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_paycycle_reserve_tests, BasicTestingSetup)

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

std::string Published(modelnet::SwarmPayCycle& cycle, const std::string& nonce)
{
    std::string err;
    BOOST_REQUIRE(cycle.Publish("chain-a", "lineage-a", nonce, "model-improvement", "policy-1", err));
    return cycle.pool_id("chain-a", "lineage-a", nonce, "model-improvement", "policy-1");
}

} // namespace

BOOST_AUTO_TEST_CASE(short_collateral_and_unknown_pool_store_nothing)
{
    modelnet::SwarmPayCycle cycle;
    const std::string id = Published(cycle, "nonce-a");
    std::string err = "prior";
    BOOST_CHECK(!cycle.Reserve(id, "txid:0", 0, err));
    BOOST_CHECK_EQUAL(err, "COLLATERAL");
    BOOST_CHECK(cycle.reserve_pool("txid:0").empty());
    BOOST_CHECK_EQUAL(cycle.balance(id), 0);

    err = "prior";
    BOOST_CHECK(!cycle.Reserve(id, "txid:0", -5, err));
    BOOST_CHECK_EQUAL(err, "COLLATERAL");

    err = "prior";
    BOOST_CHECK(!cycle.Reserve(id, "", 5, err));
    BOOST_CHECK_EQUAL(err, "COLLATERAL");
    BOOST_CHECK(cycle.reserve_role("").empty());

    err = "prior";
    BOOST_CHECK(!cycle.Reserve("missing", "txid:0", 5, err));
    BOOST_CHECK_EQUAL(err, "POOL");
    BOOST_CHECK(cycle.reserve_pool("txid:0").empty());

    err = "prior";
    BOOST_CHECK(!cycle.Reserve(id, "txid:0", 5, err, "both"));
    BOOST_CHECK_EQUAL(err, "COLLATERAL");
    BOOST_CHECK_EQUAL(cycle.balance(id), 0);
    BOOST_CHECK(!cycle.holds_money(id));
    ExpectNoSpend(cycle);
}

BOOST_AUTO_TEST_CASE(channel_adds_balance_and_escrow_does_not)
{
    modelnet::SwarmPayCycle cycle;
    const std::string id = Published(cycle, "nonce-a");
    std::string err = "prior";
    BOOST_REQUIRE(cycle.Reserve(id, "txid:0", 25, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(cycle.reserve_pool("txid:0"), id);
    BOOST_CHECK_EQUAL(cycle.reserve_role("txid:0"), modelnet::SWARM_PAYCYCLE_ROLE_CHANNEL);
    BOOST_CHECK_EQUAL(cycle.reserve_atoms("txid:0"), 25);
    BOOST_CHECK_EQUAL(cycle.balance(id), 25);
    BOOST_CHECK(!cycle.funded(id));
    BOOST_CHECK(!cycle.holds_money());
    BOOST_CHECK(!cycle.holds_money(id));
    ExpectNoSpend(cycle);

    err = "prior";
    BOOST_REQUIRE(cycle.Reserve(id, "txid:1", 9, err, modelnet::SWARM_PAYCYCLE_ROLE_ESCROW));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(cycle.reserve_role("txid:1"), modelnet::SWARM_PAYCYCLE_ROLE_ESCROW);
    BOOST_CHECK_EQUAL(cycle.reserve_atoms("txid:1"), 9);
    BOOST_CHECK_EQUAL(cycle.balance(id), 25);
    ExpectNoSpend(cycle);

    err = "prior";
    BOOST_CHECK(!cycle.Reserve(id, "txid:0", 100, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(cycle.balance(id), 25);
    BOOST_CHECK_EQUAL(cycle.reserve_atoms("txid:0"), 25);

    err = "prior";
    BOOST_CHECK(!cycle.Reserve(id, "txid:0", 4, err, modelnet::SWARM_PAYCYCLE_ROLE_ESCROW));
    BOOST_CHECK_EQUAL(err, "COLLATERAL_REUSE");
    BOOST_CHECK_EQUAL(cycle.reserve_role("txid:0"), modelnet::SWARM_PAYCYCLE_ROLE_CHANNEL);
    BOOST_CHECK_EQUAL(cycle.balance(id), 25);

    err = "prior";
    BOOST_CHECK(!cycle.Reserve(id, "txid:1", 4, err));
    BOOST_CHECK_EQUAL(err, "COLLATERAL_REUSE");
    BOOST_CHECK_EQUAL(cycle.reserve_role("txid:1"), modelnet::SWARM_PAYCYCLE_ROLE_ESCROW);
    BOOST_CHECK_EQUAL(cycle.balance(id), 25);
    ExpectNoSpend(cycle);
}

BOOST_AUTO_TEST_CASE(one_outpoint_cannot_fund_two_pools)
{
    modelnet::SwarmPayCycle cycle;
    const std::string first = Published(cycle, "nonce-a");
    const std::string second = Published(cycle, "nonce-b");
    std::string err = "prior";
    BOOST_REQUIRE(cycle.Reserve(first, "txid:0", 8, err, modelnet::SWARM_PAYCYCLE_ROLE_ESCROW));
    BOOST_CHECK_EQUAL(cycle.balance(first), 0);

    err = "prior";
    BOOST_CHECK(!cycle.Reserve(second, "txid:0", 8, err));
    BOOST_CHECK_EQUAL(err, "OUTPOINT");
    BOOST_CHECK_EQUAL(cycle.reserve_pool("txid:0"), first);
    BOOST_CHECK_EQUAL(cycle.reserve_role("txid:0"), modelnet::SWARM_PAYCYCLE_ROLE_ESCROW);
    BOOST_CHECK_EQUAL(cycle.balance(first), 0);
    BOOST_CHECK_EQUAL(cycle.balance(second), 0);
    BOOST_CHECK(cycle.reserve_pool("txid:9").empty());

    const std::string raised = cycle.pool_id("chain-a", "lineage-a", "nonce-a", "model-improvement", "policy-2");
    BOOST_REQUIRE(cycle.RaiseEpoch(first, "policy-2", err));
    BOOST_CHECK_EQUAL(cycle.reserve_pool("txid:0"), first);
    BOOST_CHECK_EQUAL(cycle.balance(first), 0);
    BOOST_CHECK_EQUAL(cycle.balance(raised), 0);
    BOOST_CHECK(!cycle.holds_money(first));
    BOOST_CHECK(!cycle.holds_money(raised));
    ExpectNoSpend(cycle);
}

BOOST_AUTO_TEST_SUITE_END()
