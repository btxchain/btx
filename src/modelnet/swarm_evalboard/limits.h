// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALBOARD_LIMITS_H
#define BITCOIN_MODELNET_SWARM_EVALBOARD_LIMITS_H

#include <cstdint>

namespace modelnet {

/** Lowest score Submit will store. */
inline constexpr int64_t kSwarmEvalScoreMin = 0;

/** Highest score Submit will store. */
inline constexpr int64_t kSwarmEvalScoreMax = 1000000;

/**
 * A subject is accepted only when the high stored score minus the low
 * stored score is at most this value. The scores themselves stay stored.
 */
inline constexpr int64_t kSwarmEvalScoreSpread = 10000;

/** This board moves no bytes. */
inline constexpr uint64_t kSwarmEvalBytesMoved = 0;

/** No GPU is run. */
inline constexpr bool kSwarmEvalGpu = false;

/** This board does not mine. */
inline constexpr bool kSwarmEvalMines = false;

/** This board does not broadcast. */
inline constexpr bool kSwarmEvalBroadcasts = false;

/** Active id. Graduate does not replace it. */
inline constexpr char kSwarmEvalActiveId[] = "base";

static_assert(kSwarmEvalScoreMin == 0, "scores start at 0");
static_assert(kSwarmEvalScoreMax == 1000000, "scores stop at 1000000");
static_assert(kSwarmEvalScoreSpread == 10000, "acceptance spread is 10000");
static_assert(kSwarmEvalBytesMoved == 0, "eval board moves no bytes");
static_assert(!kSwarmEvalGpu, "eval board does not use a GPU");
static_assert(!kSwarmEvalMines, "eval board does not mine");
static_assert(!kSwarmEvalBroadcasts, "eval board does not broadcast");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALBOARD_LIMITS_H
