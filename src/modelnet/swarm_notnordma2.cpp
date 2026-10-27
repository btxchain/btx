// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnordma2.h>

#include <string>

namespace modelnet {

SwarmNotNoRdma2Result SwarmNoteNotNoRdma2(const SwarmNotNoRdma2& note, std::string& err)
{
    SwarmNotNoRdma2Result result;
    result.moved = false;
    result.bytes_moved = false;
    if (note.adapter_id.empty()) {
        result.code = "ADAPTER";
        result.moved = false;
        result.bytes_moved = false;
        err = "ADAPTER";
        return result;
    }
    // Missing RDMA moves no bytes.
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
