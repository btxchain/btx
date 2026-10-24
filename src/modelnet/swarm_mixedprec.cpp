// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_mixedprec.h>

#include <string>

namespace modelnet {

SwarmMixedPrecResult SwarmNoteMixedPrec(const SwarmMixedPrec& job, std::string& err)
{
    SwarmMixedPrecResult result;
    result.running = false;
    // A mixed-precision run request is held and does not run.
    if (job.job_id.empty()) {
        result.code = "JOB";
        result.running = false;
        err = "JOB";
        return result;
    }
    if (job.want_run) {
        result.code = "HELD";
        result.running = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.running = false;
    err.clear();
    return result;
}

} // namespace modelnet
