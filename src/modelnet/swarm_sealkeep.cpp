// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sealkeep.h>

namespace modelnet {

// A sealed piece opens nothing.
SwarmSealKeepResult SwarmKeepSealed(const SwarmSealKeep& piece, std::string& err)
{
    SwarmSealKeepResult result;
    result.opened = false;
    result.bytes_moved = 0;

    if (piece.piece_id.empty()) {
        result.code = "PIECE";
        err = "PIECE";
        return result;
    }
    if (piece.sealed) {
        result.code = "NOT_OPENED";
        err = "NOT_OPENED";
        return result;
    }
    if (piece.want_open) {
        result.code = "HELD";
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
