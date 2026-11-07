// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CURSORFENCE_LIMITS_H
#define BITCOIN_MODELNET_SWARM_CURSORFENCE_LIMITS_H

#include <cstdint>

namespace modelnet {

/** Cursor value before any successful Advance. */
inline constexpr int64_t kSwarmCursorFenceOrigin = 0;

/** The only delta Advance accepts. */
inline constexpr int64_t kSwarmCursorFenceStep = 1;

/** This plane moves no bytes. */
inline constexpr int64_t kSwarmCursorFenceBytesMoved = 0;

/** This plane does not mine. */
inline constexpr bool kSwarmCursorFenceMined = false;

/** Mine leaves the block count here. */
inline constexpr int64_t kSwarmCursorFenceBlocks = 0;

static_assert(kSwarmCursorFenceOrigin == 0, "the cursor starts at 0");
static_assert(kSwarmCursorFenceStep == 1, "the cursor advances only by exactly 1");
static_assert(kSwarmCursorFenceBytesMoved == 0, "a cursor advance moves no bytes");
static_assert(!kSwarmCursorFenceMined, "a cursor advance does not mine");
static_assert(kSwarmCursorFenceBlocks == 0, "Mine leaves blocks at 0");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CURSORFENCE_LIMITS_H
