// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NICHESLOTS_CODES_H
#define BITCOIN_MODELNET_SWARM_NICHESLOTS_CODES_H

namespace modelnet {

/** Niche is not general, coding, or research, or it was never opened. */
inline constexpr char kSwarmNicheSlotsNiche[] = "NICHE";

/** Slot count is below 1. Nothing is stored. */
inline constexpr char kSwarmNicheSlotsSlots[] = "SLOTS";

/** This niche is already open, or this task was already spent here. */
inline constexpr char kSwarmNicheSlotsReplay[] = "REPLAY";

/** Task text is empty. Nothing is stored. */
inline constexpr char kSwarmNicheSlotsTask[] = "TASK";

/** This niche has no slots left. Nothing is stored. */
inline constexpr char kSwarmNicheSlotsExhausted[] = "EXHAUSTED";

/** A task is not moved from one niche into another. */
inline constexpr char kSwarmNicheSlotsNotMerged[] = "NOT_MERGED";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NICHESLOTS_CODES_H
