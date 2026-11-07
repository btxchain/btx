// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_IDLEDRAIN_LIMITS_H
#define BITCOIN_MODELNET_SWARM_IDLEDRAIN_LIMITS_H

#include <cstdint>

namespace modelnet {

/** First Open assigns this many workers. */
inline constexpr int64_t kSwarmIdleDrainOpenWorkers = 1;

/** Admit refuses a count that would pass this. 64 itself is allowed. */
inline constexpr int64_t kSwarmIdleDrainWorkerCap = 64;

/** Drain stores this many workers. */
inline constexpr int64_t kSwarmIdleDrainZeroWorkers = 0;

/** This plane moves no bytes. */
inline constexpr int64_t kSwarmIdleDrainBytesMoved = 0;

/** This plane does not claim a GPU ran. */
inline constexpr bool kSwarmIdleDrainGpu = false;

/** This plane does not launch a process. */
inline constexpr bool kSwarmIdleDrainLaunched = false;

static_assert(kSwarmIdleDrainOpenWorkers == 1, "open starts one worker");
static_assert(kSwarmIdleDrainWorkerCap == 64, "idle drain admits at most 64 workers");
static_assert(kSwarmIdleDrainZeroWorkers == 0, "drain leaves no workers");
static_assert(kSwarmIdleDrainBytesMoved == 0, "idle drain moves no bytes");
static_assert(!kSwarmIdleDrainGpu, "idle drain does not use a gpu");
static_assert(!kSwarmIdleDrainLaunched, "idle drain does not launch");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_IDLEDRAIN_LIMITS_H
