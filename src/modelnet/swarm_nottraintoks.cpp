// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nottraintoks.h>

#include <string>

namespace modelnet {

SwarmNotTrainToksResult SwarmNoteNotTrainToks(const SwarmNotTrainToks& note, std::string& err)
{
    SwarmNotTrainToksResult result;
    result.published = false;
    result.tokens_per_sec = 0;
    // One SGD step is not a training token rate.
    if (note.job_id.empty()) {
        result.code = "JOB";
        result.published = false;
        result.tokens_per_sec = 0;
        err = "JOB";
        return result;
    }
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.tokens_per_sec = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.tokens_per_sec = 0;
    err.clear();
    return result;
}

} // namespace modelnet
