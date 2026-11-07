// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paycycle/swarm_paycycle.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_paycycle_pay_tests, BasicTestingSetup)

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

std::string Funded(modelnet::SwarmPayCycle& cycle, const std::string& policy)
{
    std::string err;
    BOOST_REQUIRE(cycle.Publish("chain-a", "lineage-a", "nonce-a", "specialist-training", policy, err));
    const std::string id = cycle.pool_id("chain-a", "lineage-a", "nonce-a", "specialist-training", policy);
    BOOST_REQUIRE(cycle.Fund(id, true, err));
    return id;
}

} // namespace

BOOST_AUTO_TEST_CASE(lease_requires_a_funded_pool_and_a_work_id)
{
    modelnet::SwarmPayCycle cycle;
    std::string err = "prior";
    BOOST_REQUIRE(cycle.Publish("chain-a", "lineage-a", "nonce-a", "specialist-training", "policy-1", err));
    const std::string id = cycle.pool_id("chain-a", "lineage-a", "nonce-a", "specialist-training", "policy-1");

    err = "prior";
    BOOST_CHECK(!cycle.Lease("missing", "work-1", "worker-a", err));
    BOOST_CHECK_EQUAL(err, "FUNDING");
    BOOST_CHECK(!cycle.leased("missing", "work-1"));

    err = "prior";
    BOOST_CHECK(!cycle.Lease(id, "work-1", "worker-a", err));
    BOOST_CHECK_EQUAL(err, "FUNDING");
    BOOST_CHECK(!cycle.leased(id, "work-1"));
    BOOST_CHECK_EQUAL(cycle.earned_count(), 0);

    BOOST_REQUIRE(cycle.Fund(id, true, err));
    err = "prior";
    BOOST_CHECK(!cycle.Lease(id, "", "worker-a", err));
    BOOST_CHECK_EQUAL(err, "WORK");
    err = "prior";
    BOOST_CHECK(!cycle.Lease(id, "work-1", "", err));
    BOOST_CHECK_EQUAL(err, "WORK");
    BOOST_CHECK(!cycle.leased(id, "work-1"));
    BOOST_CHECK_EQUAL(cycle.balance(id), 0);
    ExpectNoSpend(cycle);
}

BOOST_AUTO_TEST_CASE(duplicate_work_replays_and_payment_is_held)
{
    modelnet::SwarmPayCycle cycle;
    const std::string id = Funded(cycle, "policy-1");
    std::string err = "prior";
    BOOST_REQUIRE(cycle.Lease(id, "work-1", "worker-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(cycle.leased(id, "work-1"));
    BOOST_CHECK_EQUAL(cycle.worker(id, "work-1"), "worker-a");
    BOOST_CHECK(!cycle.earned(id, "work-1"));

    err = "prior";
    BOOST_CHECK(!cycle.Lease(id, "work-1", "worker-b", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(cycle.worker(id, "work-1"), "worker-a");
    BOOST_CHECK_EQUAL(cycle.balance(id), 0);
    BOOST_CHECK_EQUAL(cycle.earned_count(), 0);

    err = "prior";
    BOOST_CHECK(!cycle.Pay(id, "work-1", "profit-share", err));
    BOOST_CHECK_EQUAL(err, "REFUSED");
    BOOST_CHECK(!cycle.earned(id, "work-1"));
    BOOST_CHECK_EQUAL(cycle.earned_count(), 0);

    err = "prior";
    BOOST_CHECK(!cycle.Pay(id, "work-1", "bonus", err));
    BOOST_CHECK_EQUAL(err, "LABEL");
    BOOST_CHECK(!cycle.earned(id, "work-1"));

    err = "prior";
    BOOST_CHECK(!cycle.Pay(id, "missing-work", "work-payment", err));
    BOOST_CHECK_EQUAL(err, "WORK");
    BOOST_CHECK_EQUAL(cycle.earned_count(), 0);

    err = "prior";
    BOOST_CHECK(!cycle.Pay(id, "work-1", "profit-share", err));
    BOOST_CHECK_EQUAL(err, "REFUSED");

    err = "prior";
    BOOST_CHECK(!cycle.Pay(id, "work-1", "work-payment", err));
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(cycle.earned(id, "work-1"));
    BOOST_CHECK_EQUAL(cycle.earned_count(), 1);
    BOOST_CHECK(cycle.leased(id, "work-1"));
    BOOST_CHECK_EQUAL(cycle.balance(id), 0);
    ExpectNoSpend(cycle);

    err = "prior";
    BOOST_CHECK(!cycle.Pay(id, "work-1", "work-payment", err));
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(cycle.earned_count(), 1);
    BOOST_CHECK(cycle.earned(id, "work-1"));

    err = "prior";
    BOOST_CHECK(!cycle.Lease(id, "work-1", "worker-a", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(cycle.earned(id, "work-1"));
    ExpectNoSpend(cycle);
}

BOOST_AUTO_TEST_CASE(epoch_leaves_the_earned_row_on_the_old_id)
{
    modelnet::SwarmPayCycle cycle;
    const std::string old_id = Funded(cycle, "policy-1");
    std::string err = "prior";
    BOOST_REQUIRE(cycle.Lease(old_id, "work-1", "worker-a", err));
    BOOST_CHECK(!cycle.Pay(old_id, "work-1", "work-payment", err));
    BOOST_CHECK_EQUAL(err, "HELD");

    const std::string new_id = cycle.pool_id("chain-a", "lineage-a", "nonce-a", "specialist-training", "policy-2");
    BOOST_REQUIRE(cycle.RaiseEpoch(old_id, "policy-2", err));
    BOOST_CHECK(cycle.leased(old_id, "work-1"));
    BOOST_CHECK(cycle.earned(old_id, "work-1"));
    BOOST_CHECK_EQUAL(cycle.worker(old_id, "work-1"), "worker-a");
    BOOST_CHECK(!cycle.leased(new_id, "work-1"));
    BOOST_CHECK(!cycle.earned(new_id, "work-1"));
    BOOST_CHECK(!cycle.funded(new_id));
    BOOST_CHECK(!cycle.holds_money(new_id));
    BOOST_CHECK(cycle.holds_money(old_id));
    BOOST_CHECK_EQUAL(cycle.earned_count(), 1);
    BOOST_CHECK_EQUAL(cycle.pool_count(), 2);
    ExpectNoSpend(cycle);
}

BOOST_AUTO_TEST_SUITE_END()
