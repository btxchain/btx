// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_HOLDROT_LIMITS_H
#define BITCOIN_MODELNET_SWARM_HOLDROT_LIMITS_H

#include <cstdint>

namespace modelnet {

/** This plane moves no bytes. A recorded holdout is not a payload. */
inline constexpr int64_t kSwarmHoldoutRotateBytesMoved = 0;

/** Rotate does not touch a GPU. */
inline constexpr bool kSwarmHoldoutRotateGpu = false;

/** Rotate does not launch work. */
inline constexpr bool kSwarmHoldoutRotateLaunched = false;

/** A stored holdout is never rotating. */
inline constexpr bool kSwarmHoldoutRotateRotated = false;

static_assert(kSwarmHoldoutRotateBytesMoved == 0, "a holdout rotate moves no bytes");
static_assert(!kSwarmHoldoutRotateGpu, "a holdout rotate does not use a gpu");
static_assert(!kSwarmHoldoutRotateLaunched, "a holdout rotate does not launch");
static_assert(!kSwarmHoldoutRotateRotated, "a holdout rotate does not rotate");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_HOLDROT_LIMITS_H
