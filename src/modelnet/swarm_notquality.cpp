// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notquality.h>

namespace modelnet {

SwarmNotQualityResult SwarmNoteNotQuality(const SwarmNotQuality& note, std::string& err)
{
    SwarmNotQualityResult result;
    result.published = false;
    result.seconds = 0;
    result.reached = false;
    if (note.job_id.empty()) {
        result.code = "JOB";
        result.published = false;
        result.seconds = 0;
        result.reached = false;
        err = "JOB";
        return result;
    }
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.seconds = 0;
        result.reached = false;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.seconds = 0;
    result.reached = false;
    err.clear();
    return result;
}

} // namespace modelnet
