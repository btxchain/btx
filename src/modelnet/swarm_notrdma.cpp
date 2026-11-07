// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrdma.h>

#include <string>

namespace modelnet {

SwarmNotRdmaResult SwarmNoteNotRdma(const SwarmNotRdma& note, std::string& err)
{
    SwarmNotRdmaResult result;
    result.bytes_moved = false;
    // RDMA is not available, so this note does not transfer.
    if (note.page_id.empty()) {
        result.code = "RDMA";
        result.bytes_moved = false;
        err = "RDMA";
        return result;
    }
    // Absent RDMA refuses the note even when the caller asked to transfer.
    if (!note.rdma_present) {
        result.code = "ENGINE_ABSENT";
        result.bytes_moved = false;
        err = "ENGINE_ABSENT";
        return result;
    }
    // Present RDMA still moves no bytes from this note.
    if (note.want_transfer) {
        result.code = "HELD";
        result.bytes_moved = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
