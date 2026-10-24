// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PASSHOLD_LIMITS_H
#define BITCOIN_MODELNET_SWARM_PASSHOLD_LIMITS_H

#include <cstdint>

namespace modelnet {

/** This plane moves no bytes. A recorded name is not a payload. */
inline constexpr int64_t kSwarmPassHoldBytesMoved = 0;

/** Request does not touch a GPU. */
inline constexpr bool kSwarmPassHoldGpu = false;

/** Request does not launch work. */
inline constexpr bool kSwarmPassHoldLaunched = false;

/** A stored request is never started. */
inline constexpr bool kSwarmPassHoldStarted = false;

/** A stored request is never passed. */
inline constexpr bool kSwarmPassHoldPassed = false;

static_assert(kSwarmPassHoldBytesMoved == 0, "a passthrough hold moves no bytes");
static_assert(!kSwarmPassHoldGpu, "a passthrough hold does not use a gpu");
static_assert(!kSwarmPassHoldLaunched, "a passthrough hold does not launch");
static_assert(!kSwarmPassHoldStarted, "a passthrough hold does not start");
static_assert(!kSwarmPassHoldPassed, "a passthrough hold does not pass");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PASSHOLD_LIMITS_H
