// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_piecejoin.h>

namespace modelnet {

bool SwarmPieceJoin::Add(int index, const std::string& bytes, std::string& err)
{
    if (index < 0) {
        err = "PIECE";
        return false;
    }
    if (bytes.empty()) {
        err = "PIECE";
        return false;
    }
    if (m_pieces.find(index) != m_pieces.end()) {
        err = "REPLAY";
        return false;
    }
    m_pieces.emplace(index, bytes);
    err.clear();
    return true;
}

bool SwarmPieceJoin::Join(std::string& out, std::string& err) const
{
    if (m_pieces.empty()) {
        out.clear();
        err = "PIECE";
        return false;
    }

    int expected = 0;
    for (const auto& piece : m_pieces) {
        if (piece.first != expected) {
            out.clear();
            err = "GAP";
            return false;
        }
        ++expected;
    }

    const int last = expected - 1;
    for (const auto& piece : m_pieces) {
        if (piece.first != last && piece.second.size() != 32) {
            out.clear();
            err = "SHORT";
            return false;
        }
    }

    out.clear();
    for (const auto& piece : m_pieces) {
        out += piece.second;
    }
    err.clear();
    return true;
}

} // namespace modelnet
