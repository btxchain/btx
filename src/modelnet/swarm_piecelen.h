// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PIECELEN_H
#define BTX_MODELNET_SWARM_PIECELEN_H

#include <cstdint>
#include <string>

namespace modelnet {

/** Piece-length check only. Stores no bytes and moves none. */
class SwarmPieceLen {
public:
    static constexpr int64_t PIECE = 4194304;

    bool Accept(int64_t size, bool last, std::string& err);
    int64_t piece_bytes() const;
    bool bytes_moved() const;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PIECELEN_H
