// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_experience/reward.h>

#include <modelnet/swarm_experience/limits.h>

namespace modelnet {

int ExperienceReward(const ExperienceRow* row)
{
    if (row == nullptr) return -1;
    if (row->outcome_ppm >= kExperienceRewardThresholdPpm) return 1;
    return 0;
}

} // namespace modelnet
