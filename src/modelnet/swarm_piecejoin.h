// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PIECEJOIN_H
#define BTX_MODELNET_SWARM_PIECEJOIN_H

#include <map>
#include <string>

namespace modelnet {

/**
 * Local ordered piece join.
 *
 * Pieces join only in index order. A short piece is allowed only as the
 * last piece. A missing piece joins nothing.
 *
 * Add: a negative index is PIECE and stores nothing. Empty bytes are
 * PIECE and store nothing. A duplicate index is REPLAY and keeps the
 * first bytes. Otherwise the piece is stored, err is cleared, and Add
 * returns true.
 *
 * Join: no pieces sets err to PIECE and clears out. Stored indexes that
 * are not exactly 0..n-1 set err to GAP, clear out, and leave the pieces
 * stored. Any piece except the last whose size is not 32 sets err to
 * SHORT and clears out. Otherwise the pieces are concatenated in index
 * order into out, err is cleared, and Join returns true.
 *
 * This record does not broadcast, spend, spawn a child process, open a
 * network connection, or record a hostname or IP.
 */
class SwarmPieceJoin {
public:
    bool Add(int index, const std::string& bytes, std::string& err);
    bool Join(std::string& out, std::string& err) const;

private:
    std::map<int, std::string> m_pieces;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PIECEJOIN_H
