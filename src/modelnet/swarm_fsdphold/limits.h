// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FSDPHOLD_LIMITS_H
#define BITCOIN_MODELNET_SWARM_FSDPHOLD_LIMITS_H

#include <cstdint>

namespace modelnet {

/** This plane moves no bytes. A recorded name is not a payload. */
inline constexpr int64_t kSwarmFsdpHoldBytesMoved = 0;

/** Request does not touch a GPU. */
inline constexpr bool kSwarmFsdpHoldGpu = false;

/** Request does not launch work. */
inline constexpr bool kSwarmFsdpHoldLaunched = false;

/** A stored request is never running. */
inline constexpr bool kSwarmFsdpHoldRunning = false;

static_assert(kSwarmFsdpHoldBytesMoved == 0, "an fsdp hold moves no bytes");
static_assert(!kSwarmFsdpHoldGpu, "an fsdp hold does not use a gpu");
static_assert(!kSwarmFsdpHoldLaunched, "an fsdp hold does not launch");
static_assert(!kSwarmFsdpHoldRunning, "an fsdp hold does not run");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FSDPHOLD_LIMITS_H
