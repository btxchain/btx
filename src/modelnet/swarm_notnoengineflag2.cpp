// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoengineflag2.h>

#include <string>

namespace modelnet {

SwarmNotNoEngineFlag2Result SwarmNoteNotNoEngineFlag2(const SwarmNotNoEngineFlag2& note, std::string& err)
{
    SwarmNotNoEngineFlag2Result result;
    result.moved = false;
    result.bytes_moved = false;
    if (note.transfer_id.empty()) {
        result.code = "TRANSFER";
        result.moved = false;
        result.bytes_moved = false;
        err = "TRANSFER";
        return result;
    }
    // A caller engine flag is not a KV transfer.
    if (note.engine_flag) {
        result.code = "NOT_TRANSFER";
        result.moved = false;
        result.bytes_moved = false;
        err = "NOT_TRANSFER";
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
