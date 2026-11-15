// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoshard.h>

#include <string>

namespace modelnet {

SwarmNotNoShardResult SwarmNoteNotNoShard(const SwarmNotNoShard& note, std::string& err)
{
    // A shard request does not run multi-GPU training.
    SwarmNotNoShardResult result;
    result.sharded = false;
    result.gpu = false;
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.sharded = false;
        result.gpu = false;
        err = "RUN";
        return result;
    }
    if (note.want_shard) {
        result.code = "NOT_RUN";
        result.sharded = false;
        result.gpu = false;
        err = "NOT_RUN";
        return result;
    }
    result.code = "NOTED";
    result.sharded = false;
    result.gpu = false;
    err.clear();
    return result;
}

} // namespace modelnet
