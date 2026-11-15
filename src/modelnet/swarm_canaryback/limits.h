// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CANARYBACK_LIMITS_H
#define BITCOIN_MODELNET_SWARM_CANARYBACK_LIMITS_H

#include <cstdint>

namespace modelnet {

/** Active id before any successful Adopt. */
inline constexpr char kSwarmCanaryBackBase[] = "base";

/** This plane moves no bytes. */
inline constexpr int64_t kSwarmCanaryBackBytesMoved = 0;

/** Mine leaves the block count here. */
inline constexpr int64_t kSwarmCanaryBackBlocks = 0;

/** This plane does not claim a GPU ran. */
inline constexpr bool kSwarmCanaryBackGpu = false;

/** Graduate does not graduate the active id. */
inline constexpr bool kSwarmCanaryBackGraduated = false;

/** This plane does not mine. */
inline constexpr bool kSwarmCanaryBackMined = false;

static_assert(kSwarmCanaryBackBase[0] == 'b' && kSwarmCanaryBackBase[1] == 'a' &&
                  kSwarmCanaryBackBase[2] == 's' && kSwarmCanaryBackBase[3] == 'e' &&
                  kSwarmCanaryBackBase[4] == '\0',
              "active starts as base");
static_assert(kSwarmCanaryBackBytesMoved == 0, "a canary rollback moves no bytes");
static_assert(kSwarmCanaryBackBlocks == 0, "Mine leaves blocks at 0");
static_assert(!kSwarmCanaryBackGpu, "a canary rollback does not claim a GPU");
static_assert(!kSwarmCanaryBackGraduated, "Graduate does not graduate");
static_assert(!kSwarmCanaryBackMined, "Mine does not mine");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CANARYBACK_LIMITS_H
