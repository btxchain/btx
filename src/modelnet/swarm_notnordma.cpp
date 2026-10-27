// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnordma.h>

#include <string>

namespace modelnet {

SwarmNotNoRdmaResult SwarmNoteNotNoRdma(const SwarmNotNoRdma& note, std::string& err)
{
    SwarmNotNoRdmaResult result;
    result.moved = false;
    result.bytes_moved = false;
    // Missing RDMA moves no bytes.
    if (note.link_id.empty()) {
        result.code = "LINK";
        result.moved = false;
        result.bytes_moved = false;
        err = "LINK";
        return result;
    }
    if (note.want_move) {
        result.code = "ENGINE_ABSENT";
        result.moved = false;
        result.bytes_moved = false;
        err = "ENGINE_ABSENT";
        return result;
    }
    result.code = "NOTED";
    result.moved = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
