// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoseal2.h>

#include <string>

namespace modelnet {

SwarmNotNoSeal2Result SwarmNoteNotNoSeal2(const SwarmNotNoSeal2& note, std::string& err)
{
    SwarmNotNoSeal2Result result;
    result.opened = false;
    result.bytes_moved = false;
    if (note.piece_id.empty()) {
        result.code = "PIECE";
        result.opened = false;
        result.bytes_moved = false;
        err = "PIECE";
        return result;
    }
    // A sealed piece opens nothing.
    if (note.sealed) {
        result.code = "NOT_OPENED";
        result.opened = false;
        result.bytes_moved = false;
        err = "NOT_OPENED";
        return result;
    }
    if (note.want_open) {
        result.code = "HELD";
        result.opened = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.opened = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
