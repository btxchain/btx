// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SYNCHOLD_LIMITS_H
#define BITCOIN_MODELNET_SWARM_SYNCHOLD_LIMITS_H

#include <cstdint>

namespace modelnet {

/** This plane moves no bytes. A recorded name is not a payload. */
inline constexpr int64_t kSwarmSyncHoldBytesMoved = 0;

/** Request does not touch a GPU. */
inline constexpr bool kSwarmSyncHoldGpu = false;

/** Request does not launch work. */
inline constexpr bool kSwarmSyncHoldLaunched = false;

/** A stored request is never synced. */
inline constexpr bool kSwarmSyncHoldSynced = false;

static_assert(kSwarmSyncHoldBytesMoved == 0, "a gradient sync hold moves no bytes");
static_assert(!kSwarmSyncHoldGpu, "a gradient sync hold does not use a gpu");
static_assert(!kSwarmSyncHoldLaunched, "a gradient sync hold does not launch");
static_assert(!kSwarmSyncHoldSynced, "a gradient sync hold does not sync");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SYNCHOLD_LIMITS_H
