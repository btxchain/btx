// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_piecepipe/store.h>

#include <modelnet/swarm_piecepipe/codes.h>
#include <modelnet/swarm_piecepipe/digest.h>
#include <modelnet/swarm_piecepipe/limits.h>

#include <string>
#include <utility>
#include <vector>

namespace modelnet {

bool SwarmPiecePipeStore::Accept(const std::string& id, const std::vector<unsigned char>& body, std::string& err)
{
    // Empty and over-limit win before the stored-id check, so a second
    // offer of those shapes does not become REPLAY or CONFLICT.
    if (body.empty()) {
        err = kSwarmPiecePipePiece;
        return false;
    }
    if (body.size() > kSwarmPiecePipeBodyLimit) {
        err = kSwarmPiecePipePieceLimit;
        return false;
    }
    const auto found = m_pieces.find(id);
    if (found != m_pieces.end()) {
        if (found->second == body) {
            err = kSwarmPiecePipeReplay;
            return false;
        }
        err = kSwarmPiecePipeConflict;
        return false;
    }
    if (SwarmPiecePipeDigest(body) != id) {
        err = kSwarmPiecePipePieceDigest;
        return false;
    }
    m_pieces.emplace(id, body);
    err.clear();
    return true;
}

bool SwarmPiecePipeStore::contains(const std::string& id) const
{
    return m_pieces.find(id) != m_pieces.end();
}

bool SwarmPiecePipeStore::same(const std::string& id, const std::vector<unsigned char>& body) const
{
    const auto found = m_pieces.find(id);
    return found != m_pieces.end() && found->second == body;
}

std::size_t SwarmPiecePipeStore::count() const
{
    return m_pieces.size();
}

void SwarmPiecePipeStore::InsertNew(const std::string& id, std::vector<unsigned char> body)
{
    if (m_pieces.find(id) != m_pieces.end()) {
        return;
    }
    m_pieces.emplace(id, std::move(body));
}

bool SwarmPiecePipeStore::erase(const std::string& id)
{
    return m_pieces.erase(id) != 0;
}

} // namespace modelnet
