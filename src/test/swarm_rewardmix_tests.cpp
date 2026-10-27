// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rewardmix.h>
#include <test/util/setup_common.h>

#include <cstdint>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_rewardmix_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_pool_id_is_mix)
{
    std::string err = "prior";
    modelnet::SwarmRewardMix mix;
    mix.pool_id = "";
    mix.publish_ppm = 1000000;
    const modelnet::SwarmRewardMixResult result = modelnet::SwarmNoteRewardMix(mix, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.code, "MIX");
    BOOST_CHECK_EQUAL(err, "MIX");
}

BOOST_AUTO_TEST_CASE(negative_ppm_is_mix)
{
    std::string err = "prior";
    modelnet::SwarmRewardMix mix;
    mix.pool_id = "pool";
    mix.publish_ppm = -1;
    const modelnet::SwarmRewardMixResult result = modelnet::SwarmNoteRewardMix(mix, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.code, "MIX");
    BOOST_CHECK_EQUAL(err, "MIX");
}

BOOST_AUTO_TEST_CASE(publish_ppm_999999_and_five_zeros_is_sum)
{
    std::string err = "prior";
    modelnet::SwarmRewardMix mix;
    mix.pool_id = "pool";
    mix.publish_ppm = 999999;
    mix.train_ppm = 0;
    mix.eval_ppm = 0;
    mix.data_ppm = 0;
    mix.route_ppm = 0;
    mix.reserve_ppm = 0;
    const modelnet::SwarmRewardMixResult result = modelnet::SwarmNoteRewardMix(mix, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.code, "SUM");
    BOOST_CHECK_EQUAL(err, "SUM");
}

BOOST_AUTO_TEST_CASE(all_zero_with_want_pay_is_sum)
{
    std::string err = "prior";
    modelnet::SwarmRewardMix mix;
    mix.pool_id = "pool";
    mix.publish_ppm = 0;
    mix.train_ppm = 0;
    mix.eval_ppm = 0;
    mix.data_ppm = 0;
    mix.route_ppm = 0;
    mix.reserve_ppm = 0;
    mix.want_pay = true;
    const modelnet::SwarmRewardMixResult result = modelnet::SwarmNoteRewardMix(mix, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.code, "SUM");
    BOOST_CHECK_EQUAL(err, "SUM");
}

BOOST_AUTO_TEST_CASE(full_publish_with_want_pay_is_held)
{
    std::string err = "prior";
    modelnet::SwarmRewardMix mix;
    mix.pool_id = "pool";
    mix.publish_ppm = 1000000;
    mix.train_ppm = 0;
    mix.eval_ppm = 0;
    mix.data_ppm = 0;
    mix.route_ppm = 0;
    mix.reserve_ppm = 0;
    mix.want_pay = true;
    const modelnet::SwarmRewardMixResult result = modelnet::SwarmNoteRewardMix(mix, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(full_publish_without_want_pay_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmRewardMix mix;
    mix.pool_id = "pool";
    mix.publish_ppm = 1000000;
    mix.train_ppm = 0;
    mix.eval_ppm = 0;
    mix.data_ppm = 0;
    mix.route_ppm = 0;
    mix.reserve_ppm = 0;
    mix.want_pay = false;
    const modelnet::SwarmRewardMixResult result = modelnet::SwarmNoteRewardMix(mix, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
