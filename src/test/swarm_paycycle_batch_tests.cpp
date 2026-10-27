// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paycycle/swarm_paycycle.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_paycycle_batch_tests, BasicTestingSetup)

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

std::string Pool(modelnet::SwarmPayCycle& cycle, const std::string& nonce, bool fund)
{
    std::string err;
    BOOST_REQUIRE(cycle.Publish("chain-a", "lineage-a", nonce, "evaluation", "policy-1", err));
    const std::string id = cycle.pool_id("chain-a", "lineage-a", nonce, "evaluation", "policy-1");
    if (fund) {
        BOOST_REQUIRE(cycle.Fund(id, true, err));
    }
    return id;
}

} // namespace

BOOST_AUTO_TEST_CASE(unfunded_short_and_negative_batches_commit_nothing)
{
    modelnet::SwarmPayCycle cycle;
    const std::string from = Pool(cycle, "nonce-a", false);
    const std::string to = Pool(cycle, "nonce-b", true);
    std::string err = "prior";
    BOOST_CHECK(!cycle.ApplyBatch(from, to, "pay-1", 1, err));
    BOOST_CHECK_EQUAL(err, "FUNDING");
    BOOST_CHECK_EQUAL(cycle.sequence(), 0);

    BOOST_REQUIRE(cycle.Fund(from, true, err));
    err = "prior";
    BOOST_CHECK(!cycle.ApplyBatch(from, to, "pay-1", 0, err));
    BOOST_CHECK_EQUAL(err, "AMOUNT");
    BOOST_CHECK_EQUAL(cycle.sequence(), 0);

    err = "prior";
    BOOST_CHECK(!cycle.ApplyBatch(from, to, "pay-1", 1, err));
    BOOST_CHECK_EQUAL(err, "NEGATIVE");
    BOOST_CHECK_EQUAL(cycle.balance(from), 0);
    BOOST_CHECK_EQUAL(cycle.balance(to), 0);
    BOOST_CHECK_EQUAL(cycle.sequence(), 0);
    BOOST_CHECK_EQUAL(cycle.close_count(), 0);
    ExpectNoSpend(cycle);

    BOOST_REQUIRE(cycle.Reserve(from, "txid:0", 5, err));
    BOOST_CHECK_EQUAL(cycle.balance(from), 5);
    err = "prior";
    BOOST_REQUIRE(cycle.ApplyBatch(from, to, "pay-1", 1, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(cycle.balance(from), 4);
    BOOST_CHECK_EQUAL(cycle.balance(to), 1);
    BOOST_CHECK_EQUAL(cycle.sequence(), 1);
    ExpectNoSpend(cycle);
}

BOOST_AUTO_TEST_CASE(batches_move_memory_balances_and_close_counts_pools)
{
    modelnet::SwarmPayCycle cycle;
    const std::string from = Pool(cycle, "nonce-a", true);
    const std::string to = Pool(cycle, "nonce-b", true);
    const std::string idle = Pool(cycle, "nonce-c", true);
    const std::string unfunded = Pool(cycle, "nonce-d", false);
    std::string err = "prior";
    BOOST_REQUIRE(cycle.Reserve(from, "txid:from", 10, err));
    BOOST_REQUIRE(cycle.Reserve(unfunded, "txid:unfunded", 7, err));
    BOOST_CHECK_EQUAL(cycle.balance(from), 10);
    BOOST_CHECK_EQUAL(cycle.balance(unfunded), 7);
    BOOST_CHECK(!cycle.holds_money(unfunded));

    err = "prior";
    BOOST_REQUIRE(cycle.ApplyBatch(from, to, "pay-a", 4, err));
    BOOST_REQUIRE(cycle.ApplyBatch(from, to, "pay-b", 6, err));
    BOOST_CHECK_EQUAL(cycle.balance(from), 0);
    BOOST_CHECK_EQUAL(cycle.balance(to), 10);
    BOOST_CHECK_EQUAL(cycle.balance(idle), 0);
    BOOST_CHECK_EQUAL(cycle.sequence(), 2);
    ExpectNoSpend(cycle);

    err = "prior";
    BOOST_CHECK(!cycle.ApplyBatch(from, to, "pay-b", 1, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(cycle.balance(from), 0);
    BOOST_CHECK_EQUAL(cycle.balance(to), 10);
    BOOST_CHECK_EQUAL(cycle.sequence(), 2);

    err = "prior";
    BOOST_REQUIRE(cycle.ApplyBatch(to, to, "pay-self", 3, err));
    BOOST_CHECK_EQUAL(cycle.balance(to), 10);
    BOOST_CHECK_EQUAL(cycle.sequence(), 3);

    const int64_t closed = cycle.CloseTemplate();
    BOOST_CHECK_EQUAL(closed, 1);
    BOOST_CHECK_EQUAL(cycle.close_count(), 1);
    BOOST_CHECK(!cycle.broadcast());
    BOOST_CHECK_EQUAL(cycle.automatic_spend(), "0");
    ExpectNoSpend(cycle);

    err = "prior";
    BOOST_CHECK(!cycle.ApplyBatch(to, from, "pay-short", 11, err));
    BOOST_CHECK_EQUAL(err, "NEGATIVE");
    BOOST_CHECK_EQUAL(cycle.balance(to), 10);
    BOOST_CHECK_EQUAL(cycle.balance(from), 0);
    BOOST_CHECK_EQUAL(cycle.sequence(), 3);
    BOOST_CHECK_EQUAL(cycle.CloseTemplate(), 1);
    ExpectNoSpend(cycle);
}

BOOST_AUTO_TEST_SUITE_END()
