// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcudaops.h>

#include <string>

namespace modelnet {

SwarmNotCudaOpsResult SwarmNoteNotCudaOps(const SwarmNotCudaOps& note, std::string& err)
{
    SwarmNotCudaOpsResult result;
    result.transferred = false;
    result.bytes_moved = false;
    // Missing compiled CUDA ops move no bytes.
    if (note.engine_id.empty()) {
        result.code = "ENGINE";
        result.transferred = false;
        result.bytes_moved = false;
        err = "ENGINE";
        return result;
    }
    // Absent ops refuse the note even when the caller did not ask to transfer.
    if (!note.ops_present) {
        result.code = "ENGINE_ABSENT";
        result.transferred = false;
        result.bytes_moved = false;
        err = "ENGINE_ABSENT";
        return result;
    }
    // Present ops still move no bytes from this note.
    if (note.want_transfer) {
        result.code = "ENGINE_ABSENT";
        result.transferred = false;
        result.bytes_moved = false;
        err = "ENGINE_ABSENT";
        return result;
    }
    result.code = "NOTED";
    result.transferred = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
