// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_COLLATBOOK_LIMITS_H
#define BITCOIN_MODELNET_SWARM_COLLATBOOK_LIMITS_H

#include <cstdint>

namespace modelnet {

/** The only buckets Reserve will store. */
inline constexpr char kSwarmCollatEscrow[] = "escrow";
inline constexpr char kSwarmCollatCollateral[] = "collateral";

/** A reservation earns nothing. Atoms are not moved. */
inline constexpr int64_t kSwarmCollatEarned = 0;

/** A reservation moves no bytes. */
inline constexpr int64_t kSwarmCollatBytesMoved = 0;

/** A reservation is not broadcast. */
inline constexpr bool kSwarmCollatBroadcast = false;

static_assert(kSwarmCollatEarned == 0, "collateral reservation earns nothing");
static_assert(kSwarmCollatBytesMoved == 0, "collateral reservation moves no bytes");
static_assert(!kSwarmCollatBroadcast, "collateral reservation is not broadcast");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_COLLATBOOK_LIMITS_H
