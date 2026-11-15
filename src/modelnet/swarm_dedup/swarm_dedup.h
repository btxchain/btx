// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DEDUP_H
#define BITCOIN_MODELNET_SWARM_DEDUP_H

#include <modelnet/swarm_dedup/binding.h>
#include <modelnet/swarm_dedup/index.h>
#include <modelnet/swarm_dedup/quiet.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * In-process piece dedup book.
 *
 * This plane records which opaque peer holds which opaque piece id.
 * It does not copy bytes, open a socket, or fetch a body. Peer ids and
 * piece ids are stored as given. bytes_moved() stays 0. launched() stays
 * false. gpu() stays false. No method sets bytes_moved() above 0.
 *
 * Announce stores a holder. Empty peer is PEER. Empty piece id is PIECE.
 * is_private is PRIVATE_DATA. Those three store nothing. The same peer
 * and the same piece id again is REPLAY and keeps the first. A different
 * peer for the same piece id is another holder and returns true.
 * The piece body is not stored.
 *
 * Digest stores a binding only when digest_hex equals the piece id.
 * Empty piece id is PIECE. Empty digest_hex is DIGEST. A mismatch is
 * CONFLICT and stores nothing. The first equal binding returns true.
 * A second equal binding is REPLAY.
 *
 * Pull never copies. Empty piece id is PIECE, including when the
 * requester is also empty. Empty requester with a piece id is PEER.
 * No holder is MISSING. The requester as the only holder is ALONE.
 * Some other holder is HELD. Every pull path returns false.
 * bytes_moved() stays 0. Holding is not a transfer.
 *
 * Drop of an unknown pair is MISSING and deletes nothing. A known pair
 * removes that one holder and returns true. Other holders of the same
 * piece id stay. bytes_moved() stays 0.
 */
class SwarmPieceDedup {
public:
    bool Announce(const std::string& peer, const std::string& piece_id, bool is_private, std::string& err);
    bool Digest(const std::string& piece_id, const std::string& digest_hex, std::string& err);
    bool Pull(const std::string& requester, const std::string& piece_id, std::string& err);
    bool Drop(const std::string& peer, const std::string& piece_id, std::string& err);

    std::vector<std::string> holders(const std::string& piece_id) const;
    bool announced(const std::string& peer, const std::string& piece_id) const;
    bool digest_bound(const std::string& piece_id) const;

    std::int64_t bytes_moved() const;
    bool launched() const;
    bool gpu() const;

private:
    SwarmPieceDedupIndex m_index;
    SwarmPieceDedupBindings m_bindings;
    SwarmPieceDedupQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DEDUP_H
