// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodedup2.h>

#include <string>

namespace modelnet {

SwarmNotNoDedup2Result SwarmNoteNotNoDedup2(const SwarmNotNoDedup2& note, std::string& err)
{
    SwarmNotNoDedup2Result result;
    result.moved = false;
    result.bytes_moved = false;
    // Cross-realm dedup moves nothing.
    // moved and bytes_moved stay false on every path.
    if (note.piece_id.empty()) {
        result.code = "PIECE";
        result.moved = false;
        result.bytes_moved = false;
        err = "PIECE";
        return result;
    }
    if (note.other_realm) {
        result.code = "NOT_MOVED";
        result.moved = false;
        result.bytes_moved = false;
        err = "NOT_MOVED";
        return result;
    }
    if (note.want_move) {
        result.code = "HELD";
        result.moved = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.moved = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
