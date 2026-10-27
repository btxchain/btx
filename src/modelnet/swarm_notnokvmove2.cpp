// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnokvmove2.h>

#include <string>

namespace modelnet {

SwarmNotNoKvMove2Result SwarmNoteNotNoKvMove2(const SwarmNotNoKvMove2& note, std::string& err)
{
    SwarmNotNoKvMove2Result result;
    result.moved = false;
    result.bytes_moved = false;
    // A KV placement note moves no bytes.
    if (note.transfer_id.empty()) {
        result.code = "TRANSFER";
        result.moved = false;
        result.bytes_moved = false;
        err = "TRANSFER";
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
