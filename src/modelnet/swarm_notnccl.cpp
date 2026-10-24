// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnccl.h>

#include <string>

namespace modelnet {

SwarmNotNcclResult SwarmNoteNotNccl(const SwarmNotNccl& note, std::string& err)
{
    SwarmNotNcclResult result;
    result.synced = false;
    result.bytes_moved = false;
    // This note does not start NCCL or move bytes.
    if (note.job_id.empty()) {
        result.code = "JOB";
        result.synced = false;
        result.bytes_moved = false;
        err = "JOB";
        return result;
    }
    if (note.want_sync) {
        result.code = "ENGINE_ABSENT";
        result.synced = false;
        result.bytes_moved = false;
        err = "ENGINE_ABSENT";
        return result;
    }
    result.code = "NOTED";
    result.synced = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
