// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOSEMARGIN_LIMITS_H
#define BITCOIN_MODELNET_SWARM_CLOSEMARGIN_LIMITS_H

#include <cstdint>

namespace modelnet {

/** The close margin stays 160 blocks. */
inline constexpr int64_t kSwarmCloseMarginHoldMarginBlocks = 160;

/** This plane moves no bytes. A recorded request is not a payload. */
inline constexpr int64_t kSwarmCloseMarginHoldBytesMoved = 0;

/** Shrink does not touch a GPU. */
inline constexpr bool kSwarmCloseMarginHoldGpu = false;

/** Shrink does not launch work. */
inline constexpr bool kSwarmCloseMarginHoldLaunched = false;

/** Shrink does not mine. */
inline constexpr bool kSwarmCloseMarginHoldMined = false;

/** A stored request does not shrink the margin. */
inline constexpr bool kSwarmCloseMarginHoldShrunk = false;

static_assert(kSwarmCloseMarginHoldMarginBlocks == 160, "the close margin stays 160 blocks");
static_assert(kSwarmCloseMarginHoldBytesMoved == 0, "a close margin hold moves no bytes");
static_assert(!kSwarmCloseMarginHoldGpu, "a close margin hold does not use a gpu");
static_assert(!kSwarmCloseMarginHoldLaunched, "a close margin hold does not launch");
static_assert(!kSwarmCloseMarginHoldMined, "a close margin hold does not mine");
static_assert(!kSwarmCloseMarginHoldShrunk, "a close margin hold does not shrink");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOSEMARGIN_LIMITS_H
