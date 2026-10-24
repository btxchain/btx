// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EXPERIENCE_REWARD_H
#define BITCOIN_MODELNET_SWARM_EXPERIENCE_REWARD_H

#include <modelnet/swarm_experience/row.h>

namespace modelnet {

/**
 * Reward computed from a stored outcome. 1 when outcome_ppm >= 500000,
 * otherwise 0. A missing row returns -1. The caller does not supply this.
 */
int ExperienceReward(const ExperienceRow* row);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EXPERIENCE_REWARD_H
