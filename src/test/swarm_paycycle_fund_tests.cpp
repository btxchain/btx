// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paycycle/swarm_paycycle.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_paycycle_fund_tests, BasicTestingSetup)

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

std::string Published(modelnet::SwarmPayCycle& cycle, const std::string& policy)
{
    std::string err;
    BOOST_REQUIRE(cycle.Publish("chain-a", "lineage-a", "nonce-a", "inference-service", policy, err));
    return cycle.pool_id("chain-a", "lineage-a", "nonce-a", "inference-service", policy);
}

} // namespace

BOOST_AUTO_TEST_CASE(unknown_or_unbound_pool_stays_unfunded)
{
    modelnet::SwarmPayCycle cycle;
    const std::string id = Published(cycle, "policy-1");
    std::string err = "prior";
    BOOST_CHECK(!cycle.Fund("missing", true, err));
    BOOST_CHECK_EQUAL(err, "POOL");
    BOOST_CHECK(!cycle.funded(id));
    BOOST_CHECK(!cycle.holds_money());

    err = "prior";
    BOOST_CHECK(!cycle.Fund(id, false, err));
    BOOST_CHECK_EQUAL(err, "FUNDING");
    BOOST_CHECK(!cycle.funded(id));
    BOOST_CHECK(!cycle.holds_money());
    BOOST_CHECK(!cycle.holds_money(id));
    BOOST_CHECK_EQUAL(cycle.balance(id), 0);
    ExpectNoSpend(cycle);
}

BOOST_AUTO_TEST_CASE(refund_bound_funds_one_pool_and_assigns_no_balance)
{
    modelnet::SwarmPayCycle cycle;
    const std::string funded_id = Published(cycle, "policy-1");
    const std::string other_id = Published(cycle, "policy-2");
    std::string err = "prior";
    BOOST_REQUIRE(cycle.Fund(funded_id, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(cycle.funded(funded_id));
    BOOST_CHECK(cycle.holds_money(funded_id));
    BOOST_CHECK(cycle.holds_money());
    BOOST_CHECK(!cycle.funded(other_id));
    BOOST_CHECK(!cycle.holds_money(other_id));
    BOOST_CHECK_EQUAL(cycle.balance(funded_id), 0);
    BOOST_CHECK_EQUAL(cycle.balance(other_id), 0);
    ExpectNoSpend(cycle);

    err = "prior";
    BOOST_REQUIRE(cycle.Fund(funded_id, true, err));
    BOOST_CHECK(cycle.funded(funded_id));
    BOOST_CHECK_EQUAL(cycle.balance(funded_id), 0);

    err = "prior";
    BOOST_CHECK(!cycle.Fund(funded_id, false, err));
    BOOST_CHECK_EQUAL(err, "FUNDING");
    BOOST_CHECK(cycle.funded(funded_id));
    BOOST_CHECK(cycle.holds_money(funded_id));
    BOOST_CHECK(!cycle.holds_money(other_id));
    ExpectNoSpend(cycle);

    err = "prior";
    BOOST_CHECK(!cycle.Publish("chain-a", "lineage-a", "nonce-a", "inference-service", "policy-1", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(cycle.funded(funded_id));
    BOOST_CHECK_EQUAL(cycle.pool_count(), 2);
    ExpectNoSpend(cycle);
}

BOOST_AUTO_TEST_SUITE_END()
