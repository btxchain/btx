// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_MINEHOLD_LIMITS_H
#define BITCOIN_MODELNET_SWARM_MINEHOLD_LIMITS_H

#include <cstdint>

namespace modelnet {

/** This plane moves no bytes. A recorded name is not a payload. */
inline constexpr int64_t kSwarmMineHoldBytesMoved = 0;

/** Request does not broadcast. */
inline constexpr bool kSwarmMineHoldBroadcast = false;

/** Request does not touch a GPU. */
inline constexpr bool kSwarmMineHoldGpu = false;

/** A stored request is never mined. */
inline constexpr bool kSwarmMineHoldMined = false;

/** blocks() stays this value. Nothing is mined. */
inline constexpr int64_t kSwarmMineHoldBlocks = 0;

static_assert(kSwarmMineHoldBytesMoved == 0, "a mine hold moves no bytes");
static_assert(!kSwarmMineHoldBroadcast, "a mine hold does not broadcast");
static_assert(!kSwarmMineHoldGpu, "a mine hold does not use a gpu");
static_assert(!kSwarmMineHoldMined, "a mine hold does not mine");
static_assert(kSwarmMineHoldBlocks == 0, "a mine hold mines no blocks");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_MINEHOLD_LIMITS_H
