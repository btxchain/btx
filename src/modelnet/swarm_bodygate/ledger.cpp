// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_bodygate/ledger.h>

namespace modelnet {

bool SwarmBodyLedger::Admit(int64_t index, int64_t size, bool last, std::string& code)
{
    const auto existing = m_pieces.find(index);
    if (existing != m_pieces.end()) {
        code = kSwarmBodyGateReplay;
        return false;
    }
    if (size < 1) {
        code = kSwarmBodyGateShort;
        return false;
    }
    // m_sum stays within the cap, so the remaining room is non-negative.
    // A piece that would push the sum above the cap is refused.
    const int64_t room = kSwarmBodyGateBodyCap - m_sum;
    if (size > room) {
        code = kSwarmBodyGateBody;
        return false;
    }
    SwarmBodyPiece piece;
    piece.index = index;
    piece.size = size;
    piece.last = last;
    m_pieces.emplace(index, piece);
    m_sum += size;
    code.clear();
    return true;
}

int64_t SwarmBodyLedger::size_of(int64_t index) const
{
    const auto it = m_pieces.find(index);
    if (it == m_pieces.end()) {
        return 0;
    }
    return it->second.size;
}

bool SwarmBodyLedger::last_of(int64_t index) const
{
    const auto it = m_pieces.find(index);
    if (it == m_pieces.end()) {
        return false;
    }
    return it->second.last;
}

} // namespace modelnet
