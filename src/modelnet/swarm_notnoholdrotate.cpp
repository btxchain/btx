// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoholdrotate.h>

#include <string>

namespace modelnet {

SwarmNotNoHoldRotateResult SwarmNoteNotNoHoldRotate(const SwarmNotNoHoldRotate& note, std::string& err)
{
    SwarmNotNoHoldRotateResult result;
    result.trained = false;
    result.admitted = false;
    // A fixed holdout is not a rotating holdout and trains nothing.
    if (note.eval_id.empty()) {
        result.code = "EVAL";
        result.trained = false;
        result.admitted = false;
        err = "EVAL";
        return result;
    }
    if (note.fixed_holdout) {
        result.code = "NOT_ROTATED";
        result.trained = false;
        result.admitted = false;
        err = "NOT_ROTATED";
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
