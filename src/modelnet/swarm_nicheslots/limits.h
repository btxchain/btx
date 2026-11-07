// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NICHESLOTS_LIMITS_H
#define BITCOIN_MODELNET_SWARM_NICHESLOTS_LIMITS_H

#include <cstdint>

namespace modelnet {

/** Smallest slot count Open will store. */
inline constexpr int64_t kSwarmNicheSlotsMin = 1;

/** Remaining() when that niche has no stored row. */
inline constexpr int64_t kSwarmNicheSlotsAbsent = -1;

/** This plane moves no bytes. */
inline constexpr uint64_t kSwarmNicheSlotsBytesMoved = 0;

/** This plane does not broadcast. */
inline constexpr bool kSwarmNicheSlotsBroadcast = false;

/** The only niche names Open will store. */
inline constexpr char kSwarmNicheSlotsGeneral[] = "general";
inline constexpr char kSwarmNicheSlotsCoding[] = "coding";
inline constexpr char kSwarmNicheSlotsResearch[] = "research";

static_assert(kSwarmNicheSlotsMin == 1, "a niche opens with at least one slot");
static_assert(kSwarmNicheSlotsAbsent == -1, "an unopened niche reports -1");
static_assert(kSwarmNicheSlotsBytesMoved == 0, "niche slots move no bytes");
static_assert(!kSwarmNicheSlotsBroadcast, "niche slots do not broadcast");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NICHESLOTS_LIMITS_H
