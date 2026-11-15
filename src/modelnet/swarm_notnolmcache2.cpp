// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnolmcache2.h>

#include <string>

namespace modelnet {

SwarmNotNoLmcache2Result SwarmNoteNotNoLmcache2(const SwarmNotNoLmcache2& note, std::string& err)
{
    SwarmNotNoLmcache2Result result;
    result.moved = false;
    result.bytes_moved = false;
    if (note.adapter_id.empty()) {
        result.code = "ADAPTER";
        result.moved = false;
        result.bytes_moved = false;
        err = "ADAPTER";
        return result;
    }
    // Missing LMCache CUDA ops move no bytes.
    if (!note.cuda_ops) {
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
