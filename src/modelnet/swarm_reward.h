// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_REWARD_H
#define BTX_MODELNET_SWARM_REWARD_H

#include <string>

namespace modelnet {

/**
 * One reward admission. evidence is the record being admitted. This
 * request does not train and does not update a policy.
 */
struct SwarmRewardRequest {
    std::string trajectory_id;
    std::string reward_id;
    std::string evidence;
    bool objective_reward_present{false};
};

/**
 * Admission answer. learned and policy_updated stay false: admitting
 * evidence does not train.
 */
struct SwarmRewardResult {
    bool admitted{false};
    bool learned{false};
    bool policy_updated{false};
    std::string code;
};

/**
 * Admits one reward for a trajectory. learned and policy_updated stay
 * false: admitting evidence does not train.
 *
 * Order: an empty trajectory_id or reward_id is REWARD. A request without
 * an objective reward is REWARD. Empty evidence is EVIDENCE. Otherwise the
 * result is ADMITTED, admitted is true, err is cleared, and learned and
 * policy_updated stay false.
 */
SwarmRewardResult SwarmAdmitReward(const SwarmRewardRequest& request, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_REWARD_H
