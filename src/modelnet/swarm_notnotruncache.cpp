// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotruncache.h>

#include <string>

namespace modelnet {

SwarmNotNoTruncacheResult SwarmNoteNotNoTruncache(const SwarmNotNoTruncache& note, std::string& err)
{
    SwarmNotNoTruncacheResult result;
    result.moved = false;
    result.bytes_moved = false;
    // A truncated cache piece moves no bytes.
    if (note.piece_id.empty()) {
        result.code = "PIECE";
        result.moved = false;
        result.bytes_moved = false;
        err = "PIECE";
        return result;
    }
    if (note.truncated) {
        result.code = "INCOMPLETE";
        result.moved = false;
        result.bytes_moved = false;
        err = "INCOMPLETE";
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
