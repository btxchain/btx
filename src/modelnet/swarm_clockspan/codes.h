// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOCKSPAN_CODES_H
#define BITCOIN_MODELNET_SWARM_CLOCKSPAN_CODES_H

namespace modelnet {

/** seconds is below 1. Nothing is stored. */
inline constexpr char kSwarmClockSpanRange[] = "RANGE";

/** seconds is positive and is not 90. Nothing is stored. */
inline constexpr char kSwarmClockSpanSpacing[] = "SPACING";

/** A second Note of 90. The first spacing stays. */
inline constexpr char kSwarmClockSpanReplay[] = "REPLAY";

/**
 * ClaimDeadline is not a wall-clock deadline.
 * The call does not mine and does not change the stored spacing.
 */
inline constexpr char kSwarmClockSpanNotDeadline[] = "NOT_DEADLINE";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOCKSPAN_CODES_H
