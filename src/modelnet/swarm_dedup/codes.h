// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DEDUP_CODES_H
#define BITCOIN_MODELNET_SWARM_DEDUP_CODES_H

namespace modelnet {

/** Empty peer id on announce, or empty requester on pull. Nothing is stored. */
inline constexpr char kSwarmPieceDedupPeer[] = "PEER";

/** Empty piece id. Nothing is stored. */
inline constexpr char kSwarmPieceDedupPiece[] = "PIECE";

/** A private announce is refused. Nothing is stored. */
inline constexpr char kSwarmPieceDedupPrivateData[] = "PRIVATE_DATA";

/** The same peer and piece, or the same equal digest, was offered again. The first stays. */
inline constexpr char kSwarmPieceDedupReplay[] = "REPLAY";

/** digest_hex is not the piece id. Nothing new is stored. */
inline constexpr char kSwarmPieceDedupConflict[] = "CONFLICT";

/** digest_hex is empty. Nothing is stored. */
inline constexpr char kSwarmPieceDedupDigest[] = "DIGEST";

/** No holder has announced the piece, or the peer and piece pair is not recorded. */
inline constexpr char kSwarmPieceDedupMissing[] = "MISSING";

/** The only holder of the piece is the requester. Nothing is copied. */
inline constexpr char kSwarmPieceDedupAlone[] = "ALONE";

/** Some other peer holds the piece. Holding is not a transfer. */
inline constexpr char kSwarmPieceDedupHeld[] = "HELD";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DEDUP_CODES_H
