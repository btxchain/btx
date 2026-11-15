// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnostep.h>

namespace modelnet {

SwarmNotNoStepResult SwarmNoteNotNoStep(const SwarmNotNoStep& note, std::string& err)
{
    SwarmNotNoStepResult result;
    result.distributed = false;
    result.trained = false;
    if (note.step_id.empty()) {
        result.code = "STEP";
        result.distributed = false;
        result.trained = false;
        err = "STEP";
        return result;
    }
    if (!(note.steps > 1)) {
        result.code = "NOT_DISTRIBUTED";
        result.distributed = false;
        result.trained = false;
        err = "NOT_DISTRIBUTED";
        return result;
    }
    if (note.want_distributed) {
        result.code = "NOT_DISTRIBUTED";
        result.distributed = false;
        result.trained = false;
        err = "NOT_DISTRIBUTED";
        return result;
    }
    result.code = "NOTED";
    result.distributed = false;
    result.trained = false;
    err.clear();
    return result;
}

} // namespace modelnet
