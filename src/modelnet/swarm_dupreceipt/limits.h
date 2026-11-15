// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DUPRECEIPT_LIMITS_H
#define BITCOIN_MODELNET_SWARM_DUPRECEIPT_LIMITS_H

#include <cstdint>

namespace modelnet {

/** Smallest atoms Pay will add. Anything lower is ATOMS. */
inline constexpr int64_t kSwarmDupMinAtoms = 1;

/** This plane moves no bytes. */
inline constexpr int64_t kSwarmDupBytesMoved = 0;

/** Bind and Pay do not broadcast. */
inline constexpr bool kSwarmDupBroadcast = false;

/** This plane does not mine. */
inline constexpr bool kSwarmDupMined = false;

/** automatic_spend() stays this value. Nothing is spent. */
inline constexpr char kSwarmDupAutomaticSpend[] = "0";

static_assert(kSwarmDupMinAtoms == 1, "pay atoms start at 1");
static_assert(kSwarmDupBytesMoved == 0, "duplicate receipt moves no bytes");
static_assert(!kSwarmDupBroadcast, "duplicate receipt does not broadcast");
static_assert(!kSwarmDupMined, "duplicate receipt does not mine");
static_assert(kSwarmDupAutomaticSpend[0] == '0' && kSwarmDupAutomaticSpend[1] == '\0',
              "automatic spend stays 0");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DUPRECEIPT_LIMITS_H
