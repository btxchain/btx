// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PIECEPIPE_CODES_H
#define BITCOIN_MODELNET_SWARM_PIECEPIPE_CODES_H

namespace modelnet {

/** Empty body, or an id that is not a stored piece. Nothing new is stored. */
inline constexpr char kSwarmPiecePipePiece[] = "PIECE";

/** Body is larger than 33554432 bytes. Nothing is stored. */
inline constexpr char kSwarmPiecePipePieceLimit[] = "PIECE_LIMIT";

/** SHA-384 of a new body does not equal the offered id. Nothing is stored. */
inline constexpr char kSwarmPiecePipePieceDigest[] = "PIECE_DIGEST";

/** The same id and the same body were offered again. The first body stays. */
inline constexpr char kSwarmPiecePipeReplay[] = "REPLAY";

/** The same id was offered with a different body. The first body stays. */
inline constexpr char kSwarmPiecePipeConflict[] = "CONFLICT";

/** The artifact is unknown, or a required slice is missing, or a drop would remove one. */
inline constexpr char kSwarmPiecePipeManifest[] = "MANIFEST";

/** A private body is refused. Nothing is stored. */
inline constexpr char kSwarmPiecePipePrivateData[] = "PRIVATE_DATA";

/** A ciphertext body is refused. Nothing is decrypted and nothing is stored. */
inline constexpr char kSwarmPiecePipeRealmSealed[] = "REALM_SEALED";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PIECEPIPE_CODES_H
