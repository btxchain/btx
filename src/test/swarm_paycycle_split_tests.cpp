// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paycycle/swarm_paycycle.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_paycycle_split_tests, BasicTestingSetup)

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

BOOST_AUTO_TEST_CASE(ppm_must_be_nonnegative_and_sum_to_one_million)
{
    modelnet::SwarmPayCycle cycle;
    std::string err = "prior";
    BOOST_CHECK(!cycle.split_ok());
    BOOST_CHECK(!cycle.Split(1000000, 0, 0, 0, 0, -1, err));
    BOOST_CHECK_EQUAL(err, "SPLIT");
    BOOST_CHECK(!cycle.split_ok());
    BOOST_CHECK_EQUAL(cycle.split_part("rollout"), 0);

    err = "prior";
    BOOST_CHECK(!cycle.Split(999999, 0, 0, 0, 0, 0, err));
    BOOST_CHECK_EQUAL(err, "SPLIT");
    BOOST_CHECK(!cycle.split_ok());

    err = "prior";
    BOOST_CHECK(!cycle.Split(1000001, 0, 0, 0, 0, 0, err));
    BOOST_CHECK_EQUAL(err, "SPLIT");
    BOOST_CHECK(!cycle.split_ok());

    err = "prior";
    BOOST_CHECK(!cycle.Split(INT64_C(6000000000000000000), 0, 0, 0, 0, 0, err));
    BOOST_CHECK_EQUAL(err, "SPLIT");
    BOOST_CHECK(!cycle.split_ok());
    BOOST_CHECK_EQUAL(cycle.pool_count(), 0);
    ExpectNoSpend(cycle);
}

BOOST_AUTO_TEST_CASE(accepted_split_is_stored_and_is_not_a_tax)
{
    modelnet::SwarmPayCycle cycle;
    std::string err = "prior";
    BOOST_REQUIRE(cycle.Publish("chain-a", "lineage-a", "nonce-a", "evaluation", "policy-1", err));
    const std::string id = cycle.pool_id("chain-a", "lineage-a", "nonce-a", "evaluation", "policy-1");
    BOOST_REQUIRE(cycle.Fund(id, true, err));
    BOOST_REQUIRE(cycle.Reserve(id, "txid:0", 1000, err));
    BOOST_CHECK_EQUAL(cycle.balance(id), 1000);

    err = "prior";
    BOOST_REQUIRE(cycle.Split(100000, 200000, 300000, 150000, 150000, 100000, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(cycle.split_ok());
    BOOST_CHECK_EQUAL(cycle.split_part("rollout"), 100000);
    BOOST_CHECK_EQUAL(cycle.split_part("negative"), 200000);
    BOOST_CHECK_EQUAL(cycle.split_part("reproduction"), 300000);
    BOOST_CHECK_EQUAL(cycle.split_part("evaluation"), 150000);
    BOOST_CHECK_EQUAL(cycle.split_part("challengers"), 150000);
    BOOST_CHECK_EQUAL(cycle.split_part("milestone"), 100000);
    BOOST_CHECK_EQUAL(cycle.split_part("tax"), -1);
    BOOST_CHECK_EQUAL(cycle.balance(id), 1000);
    BOOST_CHECK_EQUAL(cycle.pool_count(), 1);
    ExpectNoSpend(cycle);

    err = "prior";
    BOOST_CHECK(!cycle.Split(1, 1, 1, 1, 1, 1, err));
    BOOST_CHECK_EQUAL(err, "SPLIT");
    BOOST_CHECK(cycle.split_ok());
    BOOST_CHECK_EQUAL(cycle.split_part("rollout"), 100000);
    BOOST_CHECK_EQUAL(cycle.split_part("milestone"), 100000);
    BOOST_CHECK_EQUAL(cycle.balance(id), 1000);
    ExpectNoSpend(cycle);

    err = "prior";
    BOOST_REQUIRE(cycle.Split(1000000, 0, 0, 0, 0, 0, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(cycle.split_part("rollout"), 1000000);
    BOOST_CHECK_EQUAL(cycle.split_part("negative"), 0);
    BOOST_CHECK_EQUAL(cycle.balance(id), 1000);
    ExpectNoSpend(cycle);
}

BOOST_AUTO_TEST_SUITE_END()
