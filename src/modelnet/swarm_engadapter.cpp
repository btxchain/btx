// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_engadapter.h>

#include <string>

namespace modelnet {

SwarmEngAdapterResult SwarmAdaptEngine(const SwarmEngAdapter& adapter, std::string& err)
{
    // An adapter names an engine and moves no bytes.
    SwarmEngAdapterResult result;
    result.moved = false;
    result.bytes_moved = 0;
    result.advertised = false;
    if (adapter.transfer_id.empty()) {
        result.code = "TRANSFER";
        result.moved = false;
        result.bytes_moved = 0;
        result.advertised = false;
        err = "TRANSFER";
        return result;
    }
    if (adapter.engine_name.empty()) {
        result.code = "ENGINE";
        result.moved = false;
        result.bytes_moved = 0;
        result.advertised = false;
        err = "ENGINE";
        return result;
    }
    if (!adapter.installed) {
        result.code = "ENGINE_ABSENT";
        result.moved = false;
        result.bytes_moved = 0;
        result.advertised = false;
        err = "ENGINE_ABSENT";
        return result;
    }
    if (!adapter.cuda_ops) {
        result.code = "ENGINE_ABSENT";
        result.moved = false;
        result.bytes_moved = 0;
        result.advertised = false;
        err = "ENGINE_ABSENT";
        return result;
    }
    if (adapter.want_move) {
        result.code = "HELD";
        result.moved = false;
        result.bytes_moved = 0;
        result.advertised = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.moved = false;
    result.bytes_moved = 0;
    result.advertised = false;
    err.clear();
    return result;
}

} // namespace modelnet
