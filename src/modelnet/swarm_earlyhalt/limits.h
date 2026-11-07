// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EARLYHALT_LIMITS_H
#define BITCOIN_MODELNET_SWARM_EARLYHALT_LIMITS_H

#include <cstdint>

namespace modelnet {

/** Smallest budget Open will store. Anything lower is BUDGET. */
inline constexpr int64_t kSwarmEarlyHaltMinBudget = 1;

/** This plane moves no bytes. */
inline constexpr int64_t kSwarmEarlyHaltBytesMoved = 0;

/** This plane does not claim a GPU ran. */
inline constexpr bool kSwarmEarlyHaltGpu = false;

/** A successful Promote does not graduate the run. */
inline constexpr bool kSwarmEarlyHaltGraduated = false;

/** This plane does not mine. */
inline constexpr bool kSwarmEarlyHaltMined = false;

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EARLYHALT_LIMITS_H
