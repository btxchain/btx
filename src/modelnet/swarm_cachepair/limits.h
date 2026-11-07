// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CACHEPAIR_LIMITS_H
#define BITCOIN_MODELNET_SWARM_CACHEPAIR_LIMITS_H

#include <cstddef>
#include <cstdint>

namespace modelnet {

/**
 * Share records a page only when it has at least this many distinct
 * members. One member is not a pair.
 */
inline constexpr std::size_t kSwarmCachePairShareMin = 2;

/** This plane moves no bytes. */
inline constexpr int64_t kSwarmCachePairBytesMoved = 0;

/** A recorded pair does not take a CUDA buffer. */
inline constexpr bool kSwarmCachePairCudaBuffer = false;

/** A recorded pair starts no process. */
inline constexpr bool kSwarmCachePairLaunched = false;

static_assert(kSwarmCachePairShareMin == 2, "a page with one member cannot be shared");
static_assert(kSwarmCachePairBytesMoved == 0, "a recorded pair moves no bytes");
static_assert(!kSwarmCachePairCudaBuffer, "a recorded pair does not take a cuda buffer");
static_assert(!kSwarmCachePairLaunched, "a recorded pair starts no process");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CACHEPAIR_LIMITS_H
