// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DISPUTESTAY_LIMITS_H
#define BITCOIN_MODELNET_SWARM_DISPUTESTAY_LIMITS_H

#include <cstdint>

namespace modelnet {

/**
 * Smallest atom count that could be a settlement.
 * Atoms below this add nothing. Atoms at or above it are still held.
 */
inline constexpr int64_t kSwarmDisputeStayMinAtoms = 1;

/** This plane moves no atoms. A dispute cannot be settled. */
inline constexpr int64_t kSwarmDisputeStayAtomsMoved = 0;

/** A stored dispute is never settled. */
inline constexpr bool kSwarmDisputeStaySettled = false;

/** This plane moves no bytes. */
inline constexpr int64_t kSwarmDisputeStayBytesMoved = 0;

/** Open and Settle do not broadcast. */
inline constexpr bool kSwarmDisputeStayBroadcast = false;

/** This plane does not mine. */
inline constexpr bool kSwarmDisputeStayMined = false;

/** automatic_spend() stays this value. Nothing is spent. */
inline constexpr char kSwarmDisputeStayAutomaticSpend[] = "0";

static_assert(kSwarmDisputeStayMinAtoms == 1, "atoms below 1 are not a settlement");
static_assert(kSwarmDisputeStayAtomsMoved == 0, "a dispute stay moves no atoms");
static_assert(!kSwarmDisputeStaySettled, "a dispute stay is not settled");
static_assert(kSwarmDisputeStayBytesMoved == 0, "a dispute stay moves no bytes");
static_assert(!kSwarmDisputeStayBroadcast, "a dispute stay does not broadcast");
static_assert(!kSwarmDisputeStayMined, "a dispute stay does not mine");
static_assert(kSwarmDisputeStayAutomaticSpend[0] == '0' && kSwarmDisputeStayAutomaticSpend[1] == '\0',
              "automatic spend stays 0");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DISPUTESTAY_LIMITS_H
