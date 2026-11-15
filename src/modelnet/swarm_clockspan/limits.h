// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOCKSPAN_LIMITS_H
#define BITCOIN_MODELNET_SWARM_CLOCKSPAN_LIMITS_H

#include <cstdint>

namespace modelnet {

/** The only spacing Note will store. A block interval, not a deadline. */
inline constexpr int64_t kSwarmClockSpanSeconds = 90;

/** spacing() when Note has stored nothing. */
inline constexpr int64_t kSwarmClockSpanUnset = 0;

/** This plane moves no bytes. */
inline constexpr int64_t kSwarmClockSpanBytesMoved = 0;

/** Note and ClaimDeadline do not broadcast. */
inline constexpr bool kSwarmClockSpanBroadcast = false;

/** This plane does not mine. */
inline constexpr bool kSwarmClockSpanMined = false;

/** blocks() stays this value. Nothing is mined. */
inline constexpr int64_t kSwarmClockSpanBlocks = 0;

static_assert(kSwarmClockSpanSeconds == 90, "block spacing is 90 seconds");
static_assert(kSwarmClockSpanUnset == 0, "an empty plane stores no spacing");
static_assert(kSwarmClockSpanSeconds != kSwarmClockSpanUnset, "stored spacing is distinct from empty");
static_assert(kSwarmClockSpanBytesMoved == 0, "block spacing moves no bytes");
static_assert(!kSwarmClockSpanBroadcast, "block spacing does not broadcast");
static_assert(!kSwarmClockSpanMined, "block spacing does not mine");
static_assert(kSwarmClockSpanBlocks == 0, "block spacing mines no blocks");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOCKSPAN_LIMITS_H
