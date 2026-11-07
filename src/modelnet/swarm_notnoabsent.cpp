// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoabsent.h>

#include <string>

namespace modelnet {

SwarmNotNoAbsentResult SwarmNoteNotNoAbsent(const SwarmNotNoAbsent& note, std::string& err)
{
    SwarmNotNoAbsentResult result;
    result.bytes_moved = false;
    result.transferred = false;
    if (note.engine_id.empty()) {
        result.code = "ENGINE";
        result.bytes_moved = false;
        result.transferred = false;
        err = "ENGINE";
        return result;
    }
    // A missing engine moves no bytes.
    if (!note.present) {
        result.code = "ENGINE_ABSENT";
        result.bytes_moved = false;
        result.transferred = false;
        err = "ENGINE_ABSENT";
        return result;
    }
    if (note.want_move) {
        result.code = "ENGINE_ABSENT";
        result.bytes_moved = false;
        result.transferred = false;
        err = "ENGINE_ABSENT";
        return result;
    }
    result.code = "NOTED";
    result.bytes_moved = false;
    result.transferred = false;
    err.clear();
    return result;
}

} // namespace modelnet
