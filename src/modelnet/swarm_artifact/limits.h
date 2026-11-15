// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ARTIFACT_LIMITS_H
#define BITCOIN_MODELNET_SWARM_ARTIFACT_LIMITS_H

#include <cstddef>
#include <cstdint>

namespace modelnet {

/**
 * Piece size already used by SplitModelPieces and JoinModelPieces.
 * This plane does not select a different size.
 */
inline constexpr std::size_t kSwarmArtifactPieceBytes = 32;

/** Offers and the joined string stay in this process. */
inline constexpr uint64_t kSwarmArtifactBytesMoved = 0;

/** No GPU is run. */
inline constexpr bool kSwarmArtifactGpu = false;

static_assert(kSwarmArtifactPieceBytes == 32, "integer model pieces are 32 bytes");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ARTIFACT_LIMITS_H
