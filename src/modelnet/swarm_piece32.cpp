// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_piece32.h>

#include <cstdint>

namespace modelnet {

SwarmPieceBodyResult SwarmNotePieceBody(const SwarmPieceBody& body, std::string& err)
{
    SwarmPieceBodyResult result;
    result.accepted = false;
    result.bytes_moved = false;
    if (body.piece_id.empty() || body.bytes < 0) {
        result.code = "PIECE";
        err = "PIECE";
        return result;
    }
    // OVERSIZE wins even when want_store is true.
    if (body.bytes > SWARM_PIECE_BODY_CAP) {
        result.code = "OVERSIZE";
        err = "OVERSIZE";
        return result;
    }
    // This note does not store a body.
    if (body.want_store) {
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
