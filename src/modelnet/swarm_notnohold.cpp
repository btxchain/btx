// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohold.h>

namespace modelnet {

SwarmNotNoHoldResult SwarmNoteNotNoHold(const SwarmNotNoHold& note, std::string& err)
{
    SwarmNotNoHoldResult result;
    result.trained = false;
    result.evaluated = false;
    // A holdout split is not a training set and this note trains nothing.
    if (note.split_id.empty()) {
        result.code = "SPLIT";
        result.trained = false;
        result.evaluated = false;
        err = "SPLIT";
        return result;
    }
    if (note.holdout) {
        result.code = "NOT_TRAIN";
        result.trained = false;
        result.evaluated = false;
        err = "NOT_TRAIN";
        return result;
    }
    if (note.want_train) {
        result.code = "NOT_TRAIN";
        result.trained = false;
        result.evaluated = false;
        err = "NOT_TRAIN";
        return result;
    }
    result.code = "NOTED";
    result.trained = false;
    result.evaluated = false;
    err.clear();
    return result;
}

} // namespace modelnet
