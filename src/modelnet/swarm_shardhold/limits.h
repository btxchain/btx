// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SHARDHOLD_LIMITS_H
#define BITCOIN_MODELNET_SWARM_SHARDHOLD_LIMITS_H

#include <cstdint>

namespace modelnet {

/** This plane moves no bytes. A recorded name is not a payload. */
inline constexpr int64_t kSwarmShardHoldBytesMoved = 0;

/** Request does not touch a GPU. */
inline constexpr bool kSwarmShardHoldGpu = false;

/** Request does not launch work. */
inline constexpr bool kSwarmShardHoldLaunched = false;

/** A stored request is never sharded. */
inline constexpr bool kSwarmShardHoldSharded = false;

/** A stored request is never running. */
inline constexpr bool kSwarmShardHoldRunning = false;

static_assert(kSwarmShardHoldBytesMoved == 0, "a shard hold moves no bytes");
static_assert(!kSwarmShardHoldGpu, "a shard hold does not use a gpu");
static_assert(!kSwarmShardHoldLaunched, "a shard hold does not launch");
static_assert(!kSwarmShardHoldSharded, "a shard hold does not shard");
static_assert(!kSwarmShardHoldRunning, "a shard hold is not running");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SHARDHOLD_LIMITS_H
