// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dedup/index.h>

#include <cstddef>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {

bool SwarmPieceDedupIndex::Insert(const std::string& peer, const std::string& piece_id)
{
    if (peer.empty() || piece_id.empty()) {
        return false;
    }
    std::set<std::string>& peers = m_by_piece[piece_id];
    const auto inserted = peers.insert(peer);
    return inserted.second;
}

bool SwarmPieceDedupIndex::Contains(const std::string& peer, const std::string& piece_id) const
{
    const auto found = m_by_piece.find(piece_id);
    if (found == m_by_piece.end()) {
        return false;
    }
    return found->second.find(peer) != found->second.end();
}

bool SwarmPieceDedupIndex::Erase(const std::string& peer, const std::string& piece_id)
{
    const auto found = m_by_piece.find(piece_id);
    if (found == m_by_piece.end()) {
        return false;
    }
    const std::size_t removed = found->second.erase(peer);
    if (removed == 0) {
        return false;
    }
    if (found->second.empty()) {
        m_by_piece.erase(found);
    }
    return true;
}

std::vector<std::string> SwarmPieceDedupIndex::Holders(const std::string& piece_id) const
{
    const auto found = m_by_piece.find(piece_id);
    if (found == m_by_piece.end()) {
        return {};
    }
    return std::vector<std::string>(found->second.begin(), found->second.end());
}

std::size_t SwarmPieceDedupIndex::Count(const std::string& piece_id) const
{
    const auto found = m_by_piece.find(piece_id);
    if (found == m_by_piece.end()) {
        return 0;
    }
    return found->second.size();
}

bool SwarmPieceDedupIndex::OtherHolds(const std::string& piece_id, const std::string& requester) const
{
    const auto found = m_by_piece.find(piece_id);
    if (found == m_by_piece.end()) {
        return false;
    }
    for (const std::string& peer : found->second) {
        if (peer != requester) {
            return true;
        }
    }
    return false;
}

} // namespace modelnet
