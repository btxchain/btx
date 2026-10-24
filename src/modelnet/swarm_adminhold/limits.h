// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ADMINHOLD_LIMITS_H
#define BITCOIN_MODELNET_SWARM_ADMINHOLD_LIMITS_H

#include <cstddef>
#include <cstdint>

namespace modelnet {

/** Smallest refund_height Open will store. Anything lower is HEIGHT. */
inline constexpr int64_t kSwarmAdminHoldMinHeight = 1;

/**
 * Length of the sponsor refund key Open will store.
 * Any other size is KEY. The bytes are a length check only.
 */
inline constexpr std::size_t kSwarmAdminHoldSponsorKeyBytes = 1312;

/** This plane moves no bytes. */
inline constexpr int64_t kSwarmAdminHoldBytesMoved = 0;

/** Open and the refused moves do not broadcast. */
inline constexpr bool kSwarmAdminHoldBroadcast = false;

/** This plane does not mine. */
inline constexpr bool kSwarmAdminHoldMined = false;

/** automatic_spend() stays this value. Nothing is spent. */
inline constexpr char kSwarmAdminHoldAutomaticSpend[] = "0";

static_assert(kSwarmAdminHoldMinHeight == 1, "refund height starts at 1");
static_assert(kSwarmAdminHoldSponsorKeyBytes == 1312, "sponsor key length is 1312");
static_assert(kSwarmAdminHoldBytesMoved == 0, "admin hold moves no bytes");
static_assert(!kSwarmAdminHoldBroadcast, "admin hold does not broadcast");
static_assert(!kSwarmAdminHoldMined, "admin hold does not mine");
static_assert(kSwarmAdminHoldAutomaticSpend[0] == '0' && kSwarmAdminHoldAutomaticSpend[1] == '\0',
              "automatic spend stays 0");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ADMINHOLD_LIMITS_H
