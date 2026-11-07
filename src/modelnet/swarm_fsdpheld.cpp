// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fsdpheld.h>

#include <string>

namespace modelnet {

SwarmFsdpHeldResult SwarmNoteFsdpHeld(const SwarmFsdpHeld& job, std::string& err)
{
    SwarmFsdpHeldResult result;
    result.running = false;
    result.sharded = false;
    // An FSDP run request is held and does not run.
    if (job.job_id.empty()) {
        result.code = "JOB";
        result.running = false;
        result.sharded = false;
        err = "JOB";
        return result;
    }
    if (job.want_run) {
        result.code = "HELD";
        result.running = false;
        result.sharded = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.running = false;
    result.sharded = false;
    err.clear();
    return result;
}

} // namespace modelnet
