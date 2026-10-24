// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_poolrank.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_poolrank_tests, BasicTestingSetup)

static modelnet::SwarmPoolRank NotedPool()
{
    modelnet::SwarmPoolRank pool;
    pool.pool_id = "pool-1";
    pool.funded = true;
    pool.reward = 9;
    pool.expense = 4;
    pool.want_spend = false;
    return pool;
}

BOOST_AUTO_TEST_CASE(empty_pool_is_pool)
{
    modelnet::SwarmPoolRank pool = NotedPool();
    pool.pool_id.clear();
    std::string err = "prior";
    const modelnet::SwarmPoolRankResult result = modelnet::SwarmRankPoolLocal(pool, err);
    BOOST_CHECK(!result.holds_money);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.rank, 0);
    BOOST_CHECK_EQUAL(result.code, "POOL");
    BOOST_CHECK_EQUAL(err, "POOL");
}

BOOST_AUTO_TEST_CASE(funded_false_is_unfunded)
{
    modelnet::SwarmPoolRank pool = NotedPool();
    pool.funded = false;
    std::string err = "prior";
    const modelnet::SwarmPoolRankResult result = modelnet::SwarmRankPoolLocal(pool, err);
    BOOST_CHECK(!result.holds_money);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.rank, 0);
    BOOST_CHECK_EQUAL(result.code, "UNFUNDED");
    BOOST_CHECK_EQUAL(err, "UNFUNDED");
}

BOOST_AUTO_TEST_CASE(negative_reward_is_range)
{
    modelnet::SwarmPoolRank pool = NotedPool();
    pool.reward = -1;
    std::string err = "prior";
    const modelnet::SwarmPoolRankResult result = modelnet::SwarmRankPoolLocal(pool, err);
    BOOST_CHECK(!result.holds_money);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.rank, 0);
    BOOST_CHECK_EQUAL(result.code, "RANGE");
    BOOST_CHECK_EQUAL(err, "RANGE");
}

BOOST_AUTO_TEST_CASE(want_spend_is_held)
{
    modelnet::SwarmPoolRank pool = NotedPool();
    pool.funded = true;
    pool.reward = 9;
    pool.expense = 4;
    pool.want_spend = true;
    std::string err = "prior";
    const modelnet::SwarmPoolRankResult result = modelnet::SwarmRankPoolLocal(pool, err);
    BOOST_CHECK(!result.holds_money);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.rank, 5);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(funded_pool_is_noted)
{
    modelnet::SwarmPoolRank pool = NotedPool();
    pool.funded = true;
    pool.reward = 9;
    pool.expense = 4;
    pool.want_spend = false;
    std::string err = "prior";
    const modelnet::SwarmPoolRankResult result = modelnet::SwarmRankPoolLocal(pool, err);
    BOOST_CHECK(!result.holds_money);
    BOOST_CHECK(!result.spent);
    BOOST_CHECK_EQUAL(result.rank, 5);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
