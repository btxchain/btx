// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notlearner.h>

namespace modelnet {

SwarmNotLearnerResult SwarmNoteNotLearner(const SwarmNotLearner& note, std::string& err)
{
    SwarmNotLearnerResult result;
    result.queued = false;
    result.trained = false;
    // This note does not compute a reward or refresh a rollout model.
    if (note.trajectory_id.empty()) {
        result.code = "TRAJECTORY";
        result.queued = false;
        result.trained = false;
        err = "TRAJECTORY";
        return result;
    }
    if (note.want_queue) {
        result.code = "NOT_QUEUED";
        result.queued = false;
        result.trained = false;
        err = "NOT_QUEUED";
        return result;
    }
    result.code = "NOTED";
    result.queued = false;
    result.trained = false;
    err.clear();
    return result;
}

} // namespace modelnet
