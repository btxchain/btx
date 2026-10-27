// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoinit.h>

#include <string>

namespace modelnet {

SwarmNotNoInitResult SwarmNoteNotNoInit(const SwarmNotNoInit& note, std::string& err)
{
    SwarmNotNoInitResult result;
    result.trained = false;
    result.checkpoint_saved = false;
    // Initialization is not a training step and saves no checkpoint.
    if (note.step_id.empty()) {
        result.code = "STEP";
        result.trained = false;
        result.checkpoint_saved = false;
        err = "STEP";
        return result;
    }
    if (note.want_train) {
        result.code = "NOT_RUN";
        result.trained = false;
        result.checkpoint_saved = false;
        err = "NOT_RUN";
        return result;
    }
    result.code = "NOTED";
    result.trained = false;
    result.checkpoint_saved = false;
    err.clear();
    return result;
}

} // namespace modelnet
