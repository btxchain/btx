// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoengine2.h>

#include <string>

namespace modelnet {

SwarmNotNoEngine2Result SwarmNoteNotNoEngine2(const SwarmNotNoEngine2& note, std::string& err)
{
    SwarmNotNoEngine2Result result;
    result.moved = false;
    result.bytes_moved = false;
    if (note.engine_id.empty()) {
        result.code = "ENGINE";
        result.moved = false;
        result.bytes_moved = false;
        err = "ENGINE";
        return result;
    }
    // A missing engine moves no bytes.
    if (!note.present) {
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
