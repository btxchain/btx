// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GRADHOLD_LIMITS_H
#define BITCOIN_MODELNET_SWARM_GRADHOLD_LIMITS_H

#include <cstdint>

namespace modelnet {

/** This plane moves no bytes. A recorded update id is not a payload. */
inline constexpr int64_t kSwarmGradHoldBytesMoved = 0;

/** Offer and Export do not touch a GPU. */
inline constexpr bool kSwarmGradHoldGpu = false;

/** Offer and Export do not launch work. */
inline constexpr bool kSwarmGradHoldLaunched = false;

/** A stored update is never exported. */
inline constexpr bool kSwarmGradHoldExported = false;

static_assert(kSwarmGradHoldBytesMoved == 0, "a gradient hold moves no bytes");
static_assert(!kSwarmGradHoldGpu, "a gradient hold does not use a gpu");
static_assert(!kSwarmGradHoldLaunched, "a gradient hold does not launch");
static_assert(!kSwarmGradHoldExported, "a gradient hold is not exported");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GRADHOLD_LIMITS_H
