// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_mooncakeabs.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmMooncakeAbsResult SwarmNoteMooncakeAbs(const SwarmMooncakeAbs& engine, std::string& err)
{
    // A missing Mooncake adapter moves no bytes.
    SwarmMooncakeAbsResult result;
    result.moved = false;
    result.bytes_moved = 0;
    if (engine.engine_id.empty()) {
        result.code = "ENGINE";
        result.moved = false;
        result.bytes_moved = 0;
        err = "ENGINE";
        return result;
    }
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
