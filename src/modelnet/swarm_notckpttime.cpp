// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notckpttime.h>

namespace modelnet {

SwarmNotCkptTimeResult SwarmNoteNotCkptTime(const SwarmNotCkptTime& note, std::string& err)
{
    SwarmNotCkptTimeResult result;
    result.published = false;
    result.recovered = false;
    result.seconds = 0;
    if (note.job_id.empty()) {
        result.code = "JOB";
        result.published = false;
        result.recovered = false;
        result.seconds = 0;
        err = "JOB";
        return result;
    }
    if (!note.checkpoint_saved) {
        result.code = "NO_CHECKPOINT";
        result.published = false;
        result.recovered = false;
        result.seconds = 0;
        err = "NO_CHECKPOINT";
        return result;
    }
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.recovered = false;
        result.seconds = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.recovered = false;
    result.seconds = 0;
    err.clear();
    return result;
}

} // namespace modelnet
