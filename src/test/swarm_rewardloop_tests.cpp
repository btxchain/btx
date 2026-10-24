// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rewardloop.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_rewardloop_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(a_private_kind_stores_nothing)
{
    modelnet::SwarmRewardLoop loop;
    std::string err = "prior";
    BOOST_CHECK(!loop.Store("row-1", "private_prompt", 800000, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(loop.reward("row-1"), -1);
    BOOST_CHECK(loop.Queue().empty());

    BOOST_CHECK(!loop.Store("row-1", "credential", 800000, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK_EQUAL(loop.reward("row-1"), -1);
}

BOOST_AUTO_TEST_CASE(reward_is_one_at_the_threshold_and_zero_below)
{
    modelnet::SwarmRewardLoop loop;
    std::string err = "prior";
    BOOST_REQUIRE(loop.Store("high", "public_trajectory", 500000, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(loop.reward("high"), 1);

    BOOST_REQUIRE(loop.Store("top", "synthetic_trajectory", 1000000, err));
    BOOST_CHECK_EQUAL(loop.reward("top"), 1);

    BOOST_REQUIRE(loop.Store("low", "synthetic_trajectory", 499999, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(loop.reward("low"), 0);

    BOOST_REQUIRE(loop.Store("zero", "public_trajectory", 0, err));
    BOOST_CHECK_EQUAL(loop.reward("zero"), 0);
    BOOST_CHECK_EQUAL(loop.reward("absent"), -1);
}

BOOST_AUTO_TEST_CASE(empty_id_is_item_and_an_out_of_range_outcome_is_range)
{
    modelnet::SwarmRewardLoop loop;
    std::string err = "prior";
    BOOST_CHECK(!loop.Store("", "public_trajectory", 500000, err));
    BOOST_CHECK_EQUAL(err, "ITEM");
    BOOST_CHECK_EQUAL(loop.reward(""), -1);

    BOOST_CHECK(!loop.Store("wide", "public_trajectory", 1000001, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK(!loop.Store("neg", "synthetic_trajectory", -1, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK_EQUAL(loop.reward("wide"), -1);
    BOOST_CHECK_EQUAL(loop.reward("neg"), -1);
    BOOST_CHECK(loop.Queue().empty());
}

BOOST_AUTO_TEST_CASE(a_duplicate_id_is_replay)
{
    modelnet::SwarmRewardLoop loop;
    std::string err = "prior";
    BOOST_REQUIRE(loop.Store("row-1", "public_trajectory", 100000, err));
    BOOST_CHECK_EQUAL(loop.reward("row-1"), 0);
    BOOST_CHECK(!loop.Store("row-1", "synthetic_trajectory", 900000, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(loop.reward("row-1"), 0);
}

BOOST_AUTO_TEST_CASE(enqueue_keeps_order_and_a_second_enqueue_is_replay)
{
    modelnet::SwarmRewardLoop loop;
    std::string err = "prior";
    BOOST_REQUIRE(loop.Store("a", "public_trajectory", 500000, err));
    BOOST_REQUIRE(loop.Store("b", "synthetic_trajectory", 0, err));
    BOOST_REQUIRE(loop.Store("c", "public_trajectory", 1000000, err));

    BOOST_CHECK(!loop.Enqueue("missing", err));
    BOOST_CHECK_EQUAL(err, "ITEM");
    BOOST_CHECK(loop.Queue().empty());

    BOOST_REQUIRE(loop.Enqueue("a", err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(loop.Enqueue("b", err));
    BOOST_REQUIRE(loop.Enqueue("c", err));
    BOOST_REQUIRE_EQUAL(loop.Queue().size(), 3U);
    BOOST_CHECK_EQUAL(loop.Queue()[0], "a");
    BOOST_CHECK_EQUAL(loop.Queue()[1], "b");
    BOOST_CHECK_EQUAL(loop.Queue()[2], "c");

    BOOST_CHECK(!loop.Enqueue("b", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(loop.Queue().size(), 3U);
    BOOST_CHECK_EQUAL(loop.Queue()[0], "a");
    BOOST_CHECK_EQUAL(loop.Queue()[1], "b");
    BOOST_CHECK_EQUAL(loop.Queue()[2], "c");
}

BOOST_AUTO_TEST_SUITE_END()
