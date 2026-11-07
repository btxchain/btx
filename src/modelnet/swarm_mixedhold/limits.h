// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_MIXEDHOLD_LIMITS_H
#define BITCOIN_MODELNET_SWARM_MIXEDHOLD_LIMITS_H

#include <cstdint>

namespace modelnet {

/** This plane moves no bytes. A recorded name is not a payload. */
inline constexpr int64_t kSwarmMixedHoldBytesMoved = 0;

/** Request does not touch a GPU. */
inline constexpr bool kSwarmMixedHoldGpu = false;

/** Request does not launch work. */
inline constexpr bool kSwarmMixedHoldLaunched = false;

/** A stored request is never running. */
inline constexpr bool kSwarmMixedHoldRunning = false;

static_assert(kSwarmMixedHoldBytesMoved == 0, "a mixed hold moves no bytes");
static_assert(!kSwarmMixedHoldGpu, "a mixed hold does not use a gpu");
static_assert(!kSwarmMixedHoldLaunched, "a mixed hold does not launch");
static_assert(!kSwarmMixedHoldRunning, "a mixed hold is not running");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_MIXEDHOLD_LIMITS_H
