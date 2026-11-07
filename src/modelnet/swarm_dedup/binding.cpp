// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dedup/binding.h>

#include <map>
#include <string>

namespace modelnet {

bool SwarmPieceDedupBindings::Put(const std::string& piece_id, const std::string& digest_hex)
{
    if (piece_id.empty() || digest_hex.empty() || digest_hex != piece_id) {
        return false;
    }
    if (m_by_piece.find(piece_id) != m_by_piece.end()) {
        return false;
    }
    m_by_piece.emplace(piece_id, digest_hex);
    return true;
}

bool SwarmPieceDedupBindings::Bound(const std::string& piece_id) const
{
    return m_by_piece.find(piece_id) != m_by_piece.end();
}

} // namespace modelnet
