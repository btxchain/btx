// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ISLANDGATE_LIMITS_H
#define BITCOIN_MODELNET_SWARM_ISLANDGATE_LIMITS_H

#include <cstdint>

namespace modelnet {

/** This plane moves no bytes. */
inline constexpr int64_t kSwarmIslandGateBytesMoved = 0;

/** Admission does not launch a process. */
inline constexpr bool kSwarmIslandGateLaunched = false;

/** This plane does not claim a GPU ran. */
inline constexpr bool kSwarmIslandGateGpu = false;

/** An exchange does not complete. */
inline constexpr bool kSwarmIslandGateExchanged = false;

static_assert(kSwarmIslandGateBytesMoved == 0, "island admission moves no bytes");
static_assert(!kSwarmIslandGateLaunched, "island admission does not launch");
static_assert(!kSwarmIslandGateGpu, "island admission does not use a GPU");
static_assert(!kSwarmIslandGateExchanged, "an exchange moves no bytes");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ISLANDGATE_LIMITS_H
