// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DEDUP_BINDING_H
#define BITCOIN_MODELNET_SWARM_DEDUP_BINDING_H

#include <map>
#include <string>

namespace modelnet {

/**
 * Digest bindings keyed by piece id.
 * Put stores a binding only when digest_hex equals the piece id.
 * A mismatch, an empty field, or a second put leaves the map unchanged.
 * The binding is the id itself. The piece body is not stored.
 */
class SwarmPieceDedupBindings {
public:
    /**
     * Store digest_hex for piece_id once.
     * Returns false and stores nothing when either string is empty,
     * when they differ, or when piece_id is already bound.
     */
    bool Put(const std::string& piece_id, const std::string& digest_hex);

    /** True when an equal digest was stored for piece_id. */
    bool Bound(const std::string& piece_id) const;

private:
    std::map<std::string, std::string> m_by_piece;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DEDUP_BINDING_H
