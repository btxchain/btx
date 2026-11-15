// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ABLATEHOLD_LIMITS_H
#define BITCOIN_MODELNET_SWARM_ABLATEHOLD_LIMITS_H

#include <cstdint>

namespace modelnet {

/** This plane moves no bytes. A recorded name is not a payload. */
inline constexpr int64_t kSwarmAblateHoldBytesMoved = 0;

/** Request does not touch a GPU. */
inline constexpr bool kSwarmAblateHoldGpu = false;

/** Request does not launch work. */
inline constexpr bool kSwarmAblateHoldLaunched = false;

/** A stored request is never published. */
inline constexpr bool kSwarmAblateHoldPublished = false;

static_assert(kSwarmAblateHoldBytesMoved == 0, "an ablation hold moves no bytes");
static_assert(!kSwarmAblateHoldGpu, "an ablation hold does not use a gpu");
static_assert(!kSwarmAblateHoldLaunched, "an ablation hold does not launch");
static_assert(!kSwarmAblateHoldPublished, "an ablation hold is not published");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ABLATEHOLD_LIMITS_H
