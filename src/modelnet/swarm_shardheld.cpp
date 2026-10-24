// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_shardheld.h>

#include <string>

namespace modelnet {

SwarmShardHeldResult SwarmNoteShardHeld(const SwarmShardHeld& job, std::string& err)
{
    // A shard request is held and moves no bytes.
    SwarmShardHeldResult result;
    result.sharded = false;
    result.bytes_moved = 0;
    if (job.job_id.empty()) {
        result.code = "JOB";
        result.sharded = false;
        result.bytes_moved = 0;
        err = "JOB";
        return result;
    }
    if (job.want_shard) {
        result.code = "HELD";
        result.sharded = false;
        result.bytes_moved = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.sharded = false;
    result.bytes_moved = 0;
    err.clear();
    return result;
}

} // namespace modelnet
