// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_piecekeep.h>

namespace modelnet {

// The piece split stays 4194304 bytes.
SwarmPieceKeepResult SwarmKeepPieceSplit(const SwarmPieceKeep& piece, std::string& err)
{
    SwarmPieceKeepResult result;
    result.resized = false;
    result.bytes = 4194304;
    if (piece.piece_id.empty()) {
        result.code = "PIECE";
        err = "PIECE";
        result.resized = false;
        result.bytes = 4194304;
        return result;
    }
    if (piece.want_resize) {
        result.code = "HELD";
        err = "HELD";
        result.resized = false;
        result.bytes = 4194304;
        return result;
    }
    result.code = "NOTED";
    err.clear();
    result.resized = false;
    result.bytes = 4194304;
    return result;
}

} // namespace modelnet
