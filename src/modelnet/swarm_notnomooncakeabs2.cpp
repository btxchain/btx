// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomooncakeabs2.h>

#include <string>

namespace modelnet {

SwarmNotNoMooncakeAbs2Result SwarmNoteNotNoMooncakeAbs2(const SwarmNotNoMooncakeAbs2& note, std::string& err)
{
    SwarmNotNoMooncakeAbs2Result result;
    result.moved = false;
    result.bytes_moved = false;
    if (note.engine_id.empty()) {
        result.code = "ENGINE";
        result.moved = false;
        result.bytes_moved = false;
        err = "ENGINE";
        return result;
    }
    // A missing Mooncake adapter moves no bytes.
    if (note.mooncake_absent) {
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
