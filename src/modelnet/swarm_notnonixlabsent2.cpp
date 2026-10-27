// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnonixlabsent2.h>

#include <string>

namespace modelnet {

SwarmNotNoNixlAbsent2Result SwarmNoteNotNoNixlAbsent2(const SwarmNotNoNixlAbsent2& note, std::string& err)
{
    SwarmNotNoNixlAbsent2Result result;
    result.moved = false;
    result.bytes_moved = false;
    if (note.engine_id.empty()) {
        result.code = "ENGINE";
        result.moved = false;
        result.bytes_moved = false;
        err = "ENGINE";
        return result;
    }
    // A missing NIXL adapter moves no bytes.
    if (note.nixl_absent) {
        result.code = "ENGINE_ABSENT";
        result.moved = false;
        result.bytes_moved = false;
        err = "ENGINE_ABSENT";
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
