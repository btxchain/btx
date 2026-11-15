// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfinetune.h>

namespace modelnet {

SwarmNotFineTuneResult SwarmNoteNotFineTune(const SwarmNotFineTune& note, std::string& err)
{
    SwarmNotFineTuneResult result;
    if (note.job_id.empty()) {
        result.code = "JOB";
        result.published = false;
        result.trained = false;
        err = "JOB";
        return result;
    }
    if (!note.checkpoint_saved) {
        result.code = "NO_CHECKPOINT";
        result.published = false;
        result.trained = false;
        err = "NO_CHECKPOINT";
        return result;
    }
    if (note.want_publish) {
        result.code = "HELD";
        result.published = false;
        result.trained = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.trained = false;
    err.clear();
    return result;
}

} // namespace modelnet
