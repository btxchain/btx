// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DESCENDANTS_LIMITS_H
#define BITCOIN_MODELNET_SWARM_DESCENDANTS_LIMITS_H

#include <cstdint>

namespace modelnet {

/**
 * Two distinct authors accept a child when the high score minus the low
 * score is at most this value. The scores themselves stay stored.
 */
inline constexpr int64_t kDescendantScoreSpread = 10000;

/** This plane moves no bytes. */
inline constexpr uint64_t kDescendantBytesMoved = 0;

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DESCENDANTS_LIMITS_H
