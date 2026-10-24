// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notgrad.h>

#include <string>

namespace modelnet {

SwarmNotGradResult SwarmNoteNotGrad(const SwarmNotGrad& note, std::string& err)
{
    SwarmNotGradResult result;
    result.synced = false;
    // Gradient sync has not run.
    if (note.job_id.empty()) {
        result.code = "JOB";
        result.synced = false;
        err = "JOB";
        return result;
    }
    if (note.want_sync) {
        result.code = "NOT_SYNCED";
        result.synced = false;
        err = "NOT_SYNCED";
        return result;
    }
    result.code = "NOTED";
    result.synced = false;
    err.clear();
    return result;
}

} // namespace modelnet
