// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoshard2.h>

#include <string>

namespace modelnet {

SwarmNotNoShard2Result SwarmNoteNotNoShard2(const SwarmNotNoShard2& note, std::string& err)
{
    // A shard request does not run multi-GPU.
    SwarmNotNoShard2Result result;
    result.ran = false;
    result.gpus = 0;
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.ran = false;
        result.gpus = 0;
        err = "RUN";
        return result;
    }
    if (note.want_shard) {
        result.code = "NOT_RUN";
        result.ran = false;
        result.gpus = 0;
        err = "NOT_RUN";
        return result;
    }
    result.code = "NOTED";
    result.ran = false;
    result.gpus = 0;
    err.clear();
    return result;
}

} // namespace modelnet
