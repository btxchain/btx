// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paycycle/swarm_paycycle.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_paycycle_publish_tests, BasicTestingSetup)

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

BOOST_AUTO_TEST_CASE(empty_identity_stores_nothing)
{
    modelnet::SwarmPayCycle cycle;
    std::string err = "prior";
    BOOST_CHECK(!cycle.Publish("", "lineage-a", "nonce-a", "evaluation", "policy-1", err));
    BOOST_CHECK_EQUAL(err, "POOL");
    BOOST_CHECK_EQUAL(cycle.pool_count(), 0);
    BOOST_CHECK(!cycle.holds_money());

    err = "prior";
    BOOST_CHECK(!cycle.Publish("chain-a", "", "nonce-a", "evaluation", "policy-1", err));
    BOOST_CHECK_EQUAL(err, "POOL");
    BOOST_CHECK_EQUAL(cycle.pool_count(), 0);

    err = "prior";
    BOOST_CHECK(!cycle.Publish("chain-a", "lineage-a", "", "evaluation", "policy-1", err));
    BOOST_CHECK_EQUAL(err, "POOL");
    BOOST_CHECK_EQUAL(cycle.pool_count(), 0);
    BOOST_CHECK(!cycle.holds_money(""));
    ExpectNoSpend(cycle);
}

BOOST_AUTO_TEST_CASE(rejected_objective_stores_nothing)
{
    modelnet::SwarmPayCycle cycle;
    std::string err = "prior";
    BOOST_CHECK(!cycle.Publish("chain-a", "lineage-a", "nonce-a", "", "policy-1", err));
    BOOST_CHECK_EQUAL(err, "OBJECTIVE");
    BOOST_CHECK_EQUAL(cycle.pool_count(), 0);

    err = "prior";
    BOOST_CHECK(!cycle.Publish("chain-a", "lineage-a", "nonce-a", "research", "policy-1", err));
    BOOST_CHECK_EQUAL(err, "OBJECTIVE");
    BOOST_CHECK_EQUAL(cycle.pool_count(), 0);
    BOOST_CHECK(!cycle.holds_money());
    ExpectNoSpend(cycle);
}

BOOST_AUTO_TEST_CASE(accepted_objectives_are_unfunded_pools)
{
    const char* objectives[] = {"model-improvement", "specialist-training", "inference-service", "evaluation",
                                "application"};
    modelnet::SwarmPayCycle cycle;
    std::string err = "prior";
    for (const char* objective : objectives) {
        BOOST_REQUIRE(cycle.Publish("chain-a", "lineage-a", objective, objective, "policy-1", err));
        BOOST_CHECK(err.empty());
        const std::string id = cycle.pool_id("chain-a", "lineage-a", objective, objective, "policy-1");
        BOOST_CHECK(!id.empty());
        BOOST_CHECK(!cycle.funded(id));
        BOOST_CHECK(!cycle.holds_money(id));
        BOOST_CHECK_EQUAL(cycle.balance(id), 0);
    }
    BOOST_CHECK_EQUAL(cycle.pool_count(), 5);
    BOOST_CHECK(!cycle.holds_money());
    ExpectNoSpend(cycle);
}

BOOST_AUTO_TEST_CASE(pool_id_is_hash256_and_replay_keeps_the_first)
{
    modelnet::SwarmPayCycle cycle;
    std::string err = "prior";
    BOOST_REQUIRE(cycle.Publish("chain-a", "lineage-a", "nonce-a", "evaluation", "policy-1", err));
    const std::string id = cycle.pool_id("chain-a", "lineage-a", "nonce-a", "evaluation", "policy-1");
    BOOST_CHECK_EQUAL(id, "9296eb88361b41e5800e2ad09b3cc8dde9cef14634fcc8b1dc1450e33a632850");
    BOOST_CHECK_EQUAL(cycle.pool_count(), 1);
    BOOST_CHECK(!cycle.funded(id));
    BOOST_CHECK(!cycle.holds_money());
    BOOST_CHECK(!cycle.holds_money(id));

    err = "prior";
    BOOST_CHECK(!cycle.Publish("chain-a", "lineage-a", "nonce-a", "evaluation", "policy-1", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(cycle.pool_count(), 1);
    BOOST_CHECK(!cycle.funded(id));

    const std::string other = cycle.pool_id("chain-a", "lineage-a", "nonce-a", "evaluation", "policy-2");
    BOOST_CHECK_EQUAL(other, "1e10f0a7539bdd7398601cb965416941e30dcee30225c2ee66c1b8dc78b42729");
    BOOST_CHECK(other != id);
    BOOST_REQUIRE(cycle.Publish("chain-a", "lineage-a", "nonce-a", "evaluation", "policy-2", err));
    BOOST_CHECK_EQUAL(cycle.pool_count(), 2);
    BOOST_CHECK(!cycle.holds_money(other));
    ExpectNoSpend(cycle);
}

BOOST_AUTO_TEST_CASE(raise_epoch_keeps_the_old_pool)
{
    modelnet::SwarmPayCycle cycle;
    std::string err = "prior";
    BOOST_REQUIRE(cycle.Publish("chain-a", "lineage-a", "nonce-a", "evaluation", "policy-1", err));
    const std::string old_id = cycle.pool_id("chain-a", "lineage-a", "nonce-a", "evaluation", "policy-1");
    const std::string new_id = cycle.pool_id("chain-a", "lineage-a", "nonce-a", "evaluation", "policy-2");

    err = "prior";
    BOOST_CHECK(!cycle.RaiseEpoch("missing", "policy-2", err));
    BOOST_CHECK_EQUAL(err, "POOL");
    BOOST_CHECK_EQUAL(cycle.pool_count(), 1);

    err = "prior";
    BOOST_CHECK(!cycle.RaiseEpoch(old_id, "", err));
    BOOST_CHECK_EQUAL(err, "POLICY");
    BOOST_CHECK_EQUAL(cycle.pool_count(), 1);
    BOOST_CHECK(!cycle.funded(old_id));

    err = "prior";
    BOOST_CHECK(!cycle.RaiseEpoch(old_id, "policy-1", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(cycle.pool_count(), 1);

    err = "prior";
    BOOST_REQUIRE(cycle.RaiseEpoch(old_id, "policy-2", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(cycle.pool_count(), 2);
    BOOST_CHECK(!cycle.funded(old_id));
    BOOST_CHECK(!cycle.funded(new_id));
    BOOST_CHECK(!cycle.holds_money());
    BOOST_CHECK(!cycle.holds_money(new_id));
    BOOST_CHECK_EQUAL(cycle.balance(old_id), 0);
    BOOST_CHECK_EQUAL(cycle.balance(new_id), 0);

    err = "prior";
    BOOST_CHECK(!cycle.Publish("chain-a", "lineage-a", "nonce-a", "evaluation", "policy-2", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(cycle.pool_count(), 2);

    err = "prior";
    BOOST_CHECK(!cycle.Publish("chain-a", "lineage-a", "nonce-a", "evaluation", "policy-1", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(cycle.pool_count(), 2);
    ExpectNoSpend(cycle);
}

BOOST_AUTO_TEST_SUITE_END()
