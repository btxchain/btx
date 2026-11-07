// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoholdout.h>

#include <string>

namespace modelnet {

SwarmNotNoHoldoutResult SwarmNoteNotNoHoldout(const SwarmNotNoHoldout& note, std::string& err)
{
    SwarmNotNoHoldoutResult result;
    result.trained = false;
    result.admitted = false;
    // A holdout set is not a training run.
    if (note.eval_id.empty()) {
        result.code = "EVAL";
        result.trained = false;
        result.admitted = false;
        err = "EVAL";
        return result;
    }
    if (note.want_train) {
        result.code = "NOT_RUN";
        result.trained = false;
        result.admitted = false;
        err = "NOT_RUN";
        return result;
    }
    result.code = "NOTED";
    result.trained = false;
    result.admitted = false;
    err.clear();
    return result;
}

} // namespace modelnet
