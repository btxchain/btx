// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_engineflag.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmEngineFlagResult SwarmNoteEngineFlag(const SwarmEngineFlag& engine, std::string& err)
{
    SwarmEngineFlagResult result;
    result.moved = false;
    result.bytes_moved = 0;
    if (engine.engine_id.empty()) {
        result.code = "ENGINE";
        result.moved = false;
        result.bytes_moved = 0;
        err = "ENGINE";
        return result;
    }
    // An engine flag is not a transfer.
    if (engine.engine_flag) {
        result.code = "NOT_TRANSFER";
        result.moved = false;
        result.bytes_moved = 0;
        err = "NOT_TRANSFER";
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
