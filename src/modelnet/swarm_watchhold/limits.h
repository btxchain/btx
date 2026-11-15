// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WATCHHOLD_LIMITS_H
#define BITCOIN_MODELNET_SWARM_WATCHHOLD_LIMITS_H

#include <cstddef>
#include <cstdint>

namespace modelnet {

/** Smallest sequence Observe will store. Anything below is SEQUENCE. */
inline constexpr int64_t kSwarmWatchHoldMinSequence = 1;

/**
 * Blocks a refund must sit beyond the observed height.
 * refund_height below height + this value is MARGIN.
 * Equality meets the margin.
 */
inline constexpr int64_t kSwarmWatchHoldCloseMargin = 160;

/** This plane moves no bytes. */
inline constexpr int64_t kSwarmWatchHoldBytesMoved = 0;

/** This plane does not broadcast. */
inline constexpr bool kSwarmWatchHoldBroadcast = false;

/** This plane does not mine. */
inline constexpr bool kSwarmWatchHoldMined = false;

/** A watched sequence never releases a secret. */
inline constexpr bool kSwarmWatchHoldSecretReleased = false;

/** No secret bytes are stored. */
inline constexpr std::size_t kSwarmWatchHoldSecretBytes = 0;

/** A held refund is not a built transaction. */
inline constexpr bool kSwarmWatchHoldRefundBuilt = false;

static_assert(kSwarmWatchHoldMinSequence == 1, "sequence below 1 is refused");
static_assert(kSwarmWatchHoldCloseMargin == 160, "close margin is 160");
static_assert(kSwarmWatchHoldBytesMoved == 0, "a watched sequence moves no bytes");
static_assert(!kSwarmWatchHoldBroadcast, "a watched sequence does not broadcast");
static_assert(!kSwarmWatchHoldMined, "a watched sequence does not mine");
static_assert(!kSwarmWatchHoldSecretReleased, "a watched sequence does not release a secret");
static_assert(kSwarmWatchHoldSecretBytes == 0, "a watched sequence stores no secret bytes");
static_assert(!kSwarmWatchHoldRefundBuilt, "a held refund builds no transaction");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WATCHHOLD_LIMITS_H
