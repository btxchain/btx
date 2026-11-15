// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paycycle/swarm_paycycle.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_paycycle_freeze_tests, BasicTestingSetup)

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

BOOST_AUTO_TEST_CASE(freeze_keeps_earned_rows_and_blocks_reserve_and_batch)
{
    modelnet::SwarmPayCycle cycle;
    std::string err = "prior";
    BOOST_CHECK(!cycle.frozen());
    BOOST_REQUIRE(cycle.Publish("chain-a", "lineage-a", "nonce-a", "evaluation", "policy-1", err));
    BOOST_REQUIRE(cycle.Publish("chain-a", "lineage-a", "nonce-b", "evaluation", "policy-1", err));
    const std::string from = cycle.pool_id("chain-a", "lineage-a", "nonce-a", "evaluation", "policy-1");
    const std::string to = cycle.pool_id("chain-a", "lineage-a", "nonce-b", "evaluation", "policy-1");
    BOOST_REQUIRE(cycle.Fund(from, true, err));
    BOOST_REQUIRE(cycle.Fund(to, true, err));
    BOOST_REQUIRE(cycle.Reserve(from, "txid:0", 12, err));
    BOOST_REQUIRE(cycle.Lease(from, "work-1", "worker-a", err));
    BOOST_CHECK(!cycle.Pay(from, "work-1", "work-payment", err));
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!cycle.Quote(from, "4.00", err));
    BOOST_CHECK_EQUAL(err, "NOT_BALANCE");
    BOOST_CHECK_EQUAL(cycle.balance(from), 12);
    BOOST_CHECK_EQUAL(cycle.earned_count(), 1);

    err = "prior";
    BOOST_CHECK(!cycle.Freeze(err));
    BOOST_CHECK_EQUAL(err, "FREEZE");
    BOOST_CHECK(cycle.frozen());
    BOOST_CHECK(cycle.earned(from, "work-1"));
    BOOST_CHECK_EQUAL(cycle.earned_count(), 1);
    BOOST_CHECK_EQUAL(cycle.quote(from), "4.00");
    BOOST_CHECK_EQUAL(cycle.balance(from), 12);
    BOOST_CHECK(cycle.holds_money(from));
    ExpectNoSpend(cycle);

    err = "prior";
    BOOST_CHECK(!cycle.Reserve(to, "txid:1", 3, err));
    BOOST_CHECK_EQUAL(err, "FROZEN");
    BOOST_CHECK(cycle.reserve_pool("txid:1").empty());
    BOOST_CHECK_EQUAL(cycle.balance(to), 0);
    BOOST_CHECK_EQUAL(cycle.reserve_pool("txid:0"), from);

    err = "prior";
    BOOST_CHECK(!cycle.Reserve(from, "txid:2", 0, err));
    BOOST_CHECK_EQUAL(err, "FROZEN");
    BOOST_CHECK(cycle.reserve_pool("txid:2").empty());

    err = "prior";
    BOOST_CHECK(!cycle.ApplyBatch(from, to, "pay-1", 2, err));
    BOOST_CHECK_EQUAL(err, "FROZEN");
    BOOST_CHECK_EQUAL(cycle.balance(from), 12);
    BOOST_CHECK_EQUAL(cycle.balance(to), 0);
    BOOST_CHECK_EQUAL(cycle.sequence(), 0);
    BOOST_CHECK(cycle.earned(from, "work-1"));
    BOOST_CHECK_EQUAL(cycle.quote(from), "4.00");
    ExpectNoSpend(cycle);

    err = "prior";
    BOOST_CHECK(!cycle.Freeze(err));
    BOOST_CHECK_EQUAL(err, "FREEZE");
    BOOST_CHECK(cycle.frozen());
    BOOST_CHECK_EQUAL(cycle.CloseTemplate(), 1);
    BOOST_CHECK(!cycle.broadcast());
    BOOST_CHECK_EQUAL(cycle.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(cycle.atoms_moved(), 0);
    BOOST_CHECK(!cycle.launched());
    BOOST_CHECK(!cycle.gpu());
    BOOST_CHECK_EQUAL(cycle.bytes_moved(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
