// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dedup/swarm_dedup.h>

#include <modelnet/swarm_dedup/announce.h>
#include <modelnet/swarm_dedup/digest.h>
#include <modelnet/swarm_dedup/drop.h>
#include <modelnet/swarm_dedup/pull.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

bool SwarmPieceDedup::Announce(const std::string& peer, const std::string& piece_id, bool is_private, std::string& err)
{
    return SwarmPieceDedupAnnounce(m_index, peer, piece_id, is_private, err);
}

bool SwarmPieceDedup::Digest(const std::string& piece_id, const std::string& digest_hex, std::string& err)
{
    return SwarmPieceDedupDigest(m_bindings, piece_id, digest_hex, err);
}

bool SwarmPieceDedup::Pull(const std::string& requester, const std::string& piece_id, std::string& err)
{
    return SwarmPieceDedupPull(m_index, requester, piece_id, err);
}

bool SwarmPieceDedup::Drop(const std::string& peer, const std::string& piece_id, std::string& err)
{
    return SwarmPieceDedupDrop(m_index, peer, piece_id, err);
}

std::vector<std::string> SwarmPieceDedup::holders(const std::string& piece_id) const
{
    return m_index.Holders(piece_id);
}

bool SwarmPieceDedup::announced(const std::string& peer, const std::string& piece_id) const
{
    return m_index.Contains(peer, piece_id);
}

bool SwarmPieceDedup::digest_bound(const std::string& piece_id) const
{
    return m_bindings.Bound(piece_id);
}

std::int64_t SwarmPieceDedup::bytes_moved() const
{
    return m_quiet.bytes_moved();
}

bool SwarmPieceDedup::launched() const
{
    return m_quiet.launched();
}

bool SwarmPieceDedup::gpu() const
{
    return m_quiet.gpu();
}

} // namespace modelnet
