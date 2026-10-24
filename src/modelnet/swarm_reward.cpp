// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_reward.h>

namespace modelnet {
namespace {

SwarmRewardResult Reject(const std::string& code, std::string& err)
{
    SwarmRewardResult result;
    result.admitted = false;
    result.learned = false;
    result.policy_updated = false;
    result.code = code;
    err = code;
    return result;
}

} // namespace

SwarmRewardResult SwarmAdmitReward(const SwarmRewardRequest& request, std::string& err)
{
    if (request.trajectory_id.empty() || request.reward_id.empty()) {
        return Reject("REWARD", err);
    }
    if (!request.objective_reward_present) {
        return Reject("REWARD", err);
    }
    if (request.evidence.empty()) {
        return Reject("EVIDENCE", err);
    }
    SwarmRewardResult result;
    result.admitted = true;
    result.learned = false;
    result.policy_updated = false;
    result.code = "ADMITTED";
    err.clear();
    return result;
}

} // namespace modelnet
