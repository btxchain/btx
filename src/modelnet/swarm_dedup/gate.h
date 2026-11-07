// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DEDUP_GATE_H
#define BITCOIN_MODELNET_SWARM_DEDUP_GATE_H

#include <string>

namespace modelnet {

/**
 * Field checks that store nothing.
 * Announce: empty peer is PEER, then empty piece id is PIECE, then
 * is_private is PRIVATE_DATA.
 * Digest: empty piece id is PIECE, then empty digest_hex is DIGEST,
 * then a digest_hex that is not the piece id is CONFLICT.
 * Pull: empty piece id is PIECE, including when the requester is also
 * empty. Empty requester with a non-empty piece id is PEER.
 * A true return leaves err unchanged.
 */
bool SwarmPieceDedupAllowAnnounce(const std::string& peer, const std::string& piece_id, bool is_private, std::string& err);
bool SwarmPieceDedupAllowDigest(const std::string& piece_id, const std::string& digest_hex, std::string& err);
bool SwarmPieceDedupAllowPull(const std::string& requester, const std::string& piece_id, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DEDUP_GATE_H
