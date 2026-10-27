// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nixlabsent.h>

#include <string>

namespace modelnet {

SwarmNixlAbsentResult SwarmNoteNixlAbsent(const SwarmNixlAbsent& engine, std::string& err)
{
    // A missing NIXL adapter moves no bytes.
    SwarmNixlAbsentResult result;
    result.moved = false;
    result.bytes_moved = 0;
    if (engine.engine_id.empty()) {
        result.code = "ENGINE";
        result.moved = false;
        result.bytes_moved = 0;
        err = "ENGINE";
        return result;
    }
    // A missing NIXL adapter moves no bytes.
    if (engine.adapter_absent) {
        result.code = "ENGINE_ABSENT";
        result.moved = false;
        result.bytes_moved = 0;
        err = "ENGINE_ABSENT";
        return result;
    }
    if (engine.want_move) {
        result.code = "HELD";
        result.moved = false;
        result.bytes_moved = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.moved = false;
    result.bytes_moved = 0;
    err.clear();
    return result;
}

} // namespace modelnet
