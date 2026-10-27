// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PIECEPIPE_LIMITS_H
#define BITCOIN_MODELNET_SWARM_PIECEPIPE_LIMITS_H

#include <cstddef>

namespace modelnet {

/** One stored slice is at most this many bytes (4 MiB). */
inline constexpr std::size_t kSwarmPiecePipePieceBytes = 4194304;

/** One accepted or split body is at most this many bytes (32 MiB). */
inline constexpr std::size_t kSwarmPiecePipeBodyLimit = 33554432;

static_assert(kSwarmPiecePipePieceBytes == 4194304, "piece size limit is 4194304 bytes");
static_assert(kSwarmPiecePipeBodyLimit == 33554432, "body size limit is 33554432 bytes");
static_assert(4u * 1024u * 1024u == kSwarmPiecePipePieceBytes, "piece limit is 4 MiB");
static_assert(32u * 1024u * 1024u == kSwarmPiecePipeBodyLimit, "body limit is 32 MiB");
static_assert(kSwarmPiecePipeBodyLimit / kSwarmPiecePipePieceBytes == 8,
              "a full body splits into eight pieces");
static_assert(kSwarmPiecePipeBodyLimit % kSwarmPiecePipePieceBytes == 0,
              "the body limit is an exact multiple of the piece limit");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PIECEPIPE_LIMITS_H
