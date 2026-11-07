// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_piece4m.h>

#include <cstdint>

namespace modelnet {

SwarmPieceSplitResult SwarmNotePieceSplit(const SwarmPieceSplit& split, std::string& err)
{
    SwarmPieceSplitResult result;
    result.accepted = false;
    result.bytes_moved = false;
    if (split.manifest_id.empty() || split.piece_bytes < 0) {
        result.code = "PIECE";
        err = "PIECE";
        return result;
    }
    // SPLIT_CAP wins even when want_store is true.
    if (split.piece_bytes > SWARM_PIECE_SPLIT_BYTES) {
        result.code = "SPLIT_CAP";
        err = "SPLIT_CAP";
        return result;
    }
    // This note does not store a piece.
    if (split.want_store) {
        result.code = "HELD";
        result.accepted = false;
        result.bytes_moved = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.accepted = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
