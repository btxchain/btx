// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosealed2.h>

#include <string>

namespace modelnet {

SwarmNotNoSealed2Result SwarmNoteNotNoSealed2(const SwarmNotNoSealed2& note, std::string& err)
{
    SwarmNotNoSealed2Result result;
    result.opened = false;
    result.bytes_moved = false;
    if (note.piece_id.empty()) {
        result.code = "PIECE";
        result.opened = false;
        result.bytes_moved = false;
        err = "PIECE";
        return result;
    }
    // A sealed piece opens nothing and moves no bytes.
    if (note.sealed) {
        result.code = "SEALED";
        result.opened = false;
        result.bytes_moved = false;
        err = "SEALED";
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
