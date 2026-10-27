// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckptsave.h>

namespace modelnet {

SwarmCkptSaveResult SwarmNoteCkptSave(const SwarmCkptSave& job, std::string& err)
{
    // A checkpoint save request is held and saves nothing.
    SwarmCkptSaveResult result;
    result.saved = false;
    result.bytes_moved = 0;
    if (job.job_id.empty()) {
        result.code = "JOB";
        result.saved = false;
        result.bytes_moved = 0;
        err = "JOB";
        return result;
    }
    if (job.want_save) {
        result.code = "HELD";
        result.saved = false;
        result.bytes_moved = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.saved = false;
    result.bytes_moved = 0;
    err.clear();
    return result;
}

} // namespace modelnet
