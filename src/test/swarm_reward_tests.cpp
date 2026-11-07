// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_reward.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_reward_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_id_is_reward)
{
    std::string err = "prior";
    modelnet::SwarmRewardRequest request;
    request.trajectory_id = "";
    request.reward_id = "reward-1";
    request.evidence = "score";
    request.objective_reward_present = true;
    const modelnet::SwarmRewardResult empty_trajectory = modelnet::SwarmAdmitReward(request, err);
    BOOST_CHECK(!empty_trajectory.admitted);
    BOOST_CHECK(!empty_trajectory.learned);
    BOOST_CHECK(!empty_trajectory.policy_updated);
    BOOST_CHECK_EQUAL(empty_trajectory.code, "REWARD");
    BOOST_CHECK_EQUAL(err, "REWARD");

    request.trajectory_id = "traj-1";
    request.reward_id = "";
    const modelnet::SwarmRewardResult empty_reward = modelnet::SwarmAdmitReward(request, err);
    BOOST_CHECK(!empty_reward.admitted);
    BOOST_CHECK(!empty_reward.learned);
    BOOST_CHECK(!empty_reward.policy_updated);
    BOOST_CHECK_EQUAL(empty_reward.code, "REWARD");
    BOOST_CHECK_EQUAL(err, "REWARD");
}

BOOST_AUTO_TEST_CASE(missing_objective_is_reward)
{
    std::string err = "prior";
    modelnet::SwarmRewardRequest request;
    request.trajectory_id = "traj-1";
    request.reward_id = "reward-1";
    request.evidence = "score";
    request.objective_reward_present = false;
    const modelnet::SwarmRewardResult result = modelnet::SwarmAdmitReward(request, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.learned);
    BOOST_CHECK(!result.policy_updated);
    BOOST_CHECK_EQUAL(result.code, "REWARD");
    BOOST_CHECK_EQUAL(err, "REWARD");
}

BOOST_AUTO_TEST_CASE(empty_evidence_is_evidence)
{
    std::string err = "prior";
    modelnet::SwarmRewardRequest request;
    request.trajectory_id = "traj-1";
    request.reward_id = "reward-1";
    request.evidence = "";
    request.objective_reward_present = true;
    const modelnet::SwarmRewardResult result = modelnet::SwarmAdmitReward(request, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.learned);
    BOOST_CHECK(!result.policy_updated);
    BOOST_CHECK_EQUAL(result.code, "EVIDENCE");
    BOOST_CHECK_EQUAL(err, "EVIDENCE");
}

BOOST_AUTO_TEST_CASE(admitted_evidence_does_not_train)
{
    std::string err = "prior";
    modelnet::SwarmRewardRequest request;
    request.trajectory_id = "traj-1";
    request.reward_id = "reward-1";
    request.evidence = "score";
    request.objective_reward_present = true;
    const modelnet::SwarmRewardResult result = modelnet::SwarmAdmitReward(request, err);
    BOOST_CHECK(result.admitted);
    BOOST_CHECK(!result.learned);
    BOOST_CHECK(!result.policy_updated);
    BOOST_CHECK_EQUAL(result.code, "ADMITTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
