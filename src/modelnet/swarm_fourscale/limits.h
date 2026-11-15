// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FOURSCALE_LIMITS_H
#define BITCOIN_MODELNET_SWARM_FOURSCALE_LIMITS_H

#include <cstdint>

namespace modelnet {

/** online, daily, weekly, and generational. No fifth scale is planted. */
inline constexpr int kSwarmFourScaleCount = 4;

/** Open plants every scale at this step. */
inline constexpr int64_t kSwarmFourScaleInitialStep = 0;

/** Step adds this many to the named scale and to no other. */
inline constexpr int64_t kSwarmFourScaleStepIncrement = 1;

/** This plane moves no bytes. */
inline constexpr int64_t kSwarmFourScaleBytesMoved = 0;

/** This plane does not claim a GPU ran. */
inline constexpr bool kSwarmFourScaleGpu = false;

/** Graduate does not set this. graduated() stays false. */
inline constexpr bool kSwarmFourScaleGraduated = false;

static_assert(kSwarmFourScaleCount == 4, "four timescales");
static_assert(kSwarmFourScaleInitialStep == 0, "open starts at step 0");
static_assert(kSwarmFourScaleStepIncrement == 1, "a step adds one");
static_assert(kSwarmFourScaleBytesMoved == 0, "this plane moves no bytes");
static_assert(!kSwarmFourScaleGpu, "this plane does not claim a gpu");
static_assert(!kSwarmFourScaleGraduated, "graduation stays off");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FOURSCALE_LIMITS_H
