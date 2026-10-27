// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EXPERIENCE_LIMITS_H
#define BITCOIN_MODELNET_SWARM_EXPERIENCE_LIMITS_H

#include <cstdint>

namespace modelnet {

/** Inclusive ppm bounds. Values outside this closed interval are RANGE. */
inline constexpr int64_t kExperiencePpmMin = 0;
inline constexpr int64_t kExperiencePpmMax = 1000000;

/** Stored rows at or above this ppm have reward 1. Below it, reward is 0. */
inline constexpr int64_t kExperienceRewardThresholdPpm = 500000;

/** This plane moves no bytes and does not claim a GPU. */
inline constexpr uint64_t kExperienceBytesMoved = 0;

inline bool ExperienceOutcomeInRange(int64_t outcome_ppm)
{
    return outcome_ppm >= kExperiencePpmMin && outcome_ppm <= kExperiencePpmMax;
}

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EXPERIENCE_LIMITS_H
