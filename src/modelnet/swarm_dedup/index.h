// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DEDUP_INDEX_H
#define BITCOIN_MODELNET_SWARM_DEDUP_INDEX_H

#include <cstddef>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Holders of opaque piece ids.
 * The map records peer ids only. It does not store a body, a path,
 * or a byte count. Insert refuses an empty peer or an empty piece id.
 * A second insert of the same pair leaves the first in place.
 * Erase removes one peer. Other peers of that piece id stay.
 */
class SwarmPieceDedupIndex {
public:
    /**
     * Record peer as a holder of piece_id.
     * Empty peer, empty piece_id, or a pair already present returns false
     * and leaves the index unchanged.
     */
    bool Insert(const std::string& peer, const std::string& piece_id);

    /** True when this peer has announced this piece id. */
    bool Contains(const std::string& peer, const std::string& piece_id) const;

    /**
     * Remove one holder.
     * An unknown pair returns false and deletes nothing.
     * When the last holder of a piece is removed, that piece id leaves the index.
     */
    bool Erase(const std::string& peer, const std::string& piece_id);

    /** Peers that hold piece_id, in lexicographic order. Empty when none do. */
    std::vector<std::string> Holders(const std::string& piece_id) const;

    /** How many peers hold piece_id. */
    std::size_t Count(const std::string& piece_id) const;

    /**
     * True when at least one recorded holder of piece_id is not requester.
     * An unknown piece id is false.
     */
    bool OtherHolds(const std::string& piece_id, const std::string& requester) const;

private:
    std::map<std::string, std::set<std::string>> m_by_piece;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DEDUP_INDEX_H
