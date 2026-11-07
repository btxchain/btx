// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DEDUP_LIMITS_H
#define BITCOIN_MODELNET_SWARM_DEDUP_LIMITS_H

#include <cstddef>
#include <cstdint>

namespace modelnet {

/** This plane stores no piece body. */
inline constexpr std::size_t kSwarmPieceDedupBodyBytes = 0;

/** Announce, digest, pull, and drop move no bytes. */
inline constexpr std::int64_t kSwarmPieceDedupBytesMoved = 0;

/** This plane does not launch a worker. */
inline constexpr bool kSwarmPieceDedupLaunched = false;

/** This plane does not use a GPU. */
inline constexpr bool kSwarmPieceDedupGpu = false;

static_assert(kSwarmPieceDedupBodyBytes == 0, "piece dedup stores no body");
static_assert(kSwarmPieceDedupBytesMoved == 0, "piece dedup moves no bytes");
static_assert(!kSwarmPieceDedupLaunched, "piece dedup does not launch");
static_assert(!kSwarmPieceDedupGpu, "piece dedup does not use a gpu");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DEDUP_LIMITS_H
