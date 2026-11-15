// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ARTIFACT_ERROR_H
#define BITCOIN_MODELNET_SWARM_ARTIFACT_ERROR_H

namespace modelnet {

/** A second capture, or the same bytes offered again at an index. The first bytes stay. */
inline constexpr char kSwarmArtifactReplay[] = "REPLAY";

/** Split or join was asked for before a capture was stored. */
inline constexpr char kSwarmArtifactArtifact[] = "ARTIFACT";

/** A non-last piece is not 32 bytes, or the last piece is empty or longer than 32. */
inline constexpr char kSwarmArtifactShort[] = "SHORT";

/** Offer index is negative. Nothing is stored. */
inline constexpr char kSwarmArtifactIndex[] = "INDEX";

/** The same index was offered again with different bytes. The first bytes stay. */
inline constexpr char kSwarmArtifactConflict[] = "CONFLICT";

/** Join does not have indexes exactly 0..n-1. */
inline constexpr char kSwarmArtifactGap[] = "GAP";

/** Joined pieces do not reproduce the captured bytes. joined() stays false. */
inline constexpr char kSwarmArtifactMismatch[] = "MISMATCH";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ARTIFACT_ERROR_H
