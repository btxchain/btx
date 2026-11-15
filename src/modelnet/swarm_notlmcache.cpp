// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notlmcache.h>

#include <string>

namespace modelnet {

SwarmNotLmcacheResult SwarmNoteNotLmcache(const SwarmNotLmcache& note, std::string& err)
{
    SwarmNotLmcacheResult result;
    result.bytes_moved = false;
    // Missing compiled LMCache CUDA ops is not a KV transfer.
    if (note.page_id.empty()) {
        result.code = "CACHE";
        result.bytes_moved = false;
        err = "CACHE";
        return result;
    }
    // Absent ops refuse the note even when the caller asked to transfer.
    if (!note.cuda_ops_present) {
        result.code = "ENGINE_ABSENT";
        result.bytes_moved = false;
        err = "ENGINE_ABSENT";
        return result;
    }
    // Present ops still move no bytes from this note.
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
