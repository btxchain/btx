// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notzerostep.h>

#include <string>

namespace modelnet {

SwarmNotZeroStepResult SwarmNoteNotZeroStep(const SwarmNotZeroStep& note, std::string& err)
{
    SwarmNotZeroStepResult result;
    result.training = false;
    result.applied_steps = 0;
    // Zero max steps stays CPU-only. This note trains nothing.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.training = false;
        result.applied_steps = 0;
        err = "NODE";
        return result;
    }
    if (note.max_steps == 0) {
        result.code = "CPU_ONLY";
        result.training = false;
        result.applied_steps = 0;
        err = "CPU_ONLY";
        return result;
    }
    if (note.want_train) {
        result.code = "CPU_ONLY";
        result.training = false;
        result.applied_steps = 0;
        err = "CPU_ONLY";
        return result;
    }
    result.code = "NOTED";
    result.training = false;
    result.applied_steps = 0;
    err.clear();
    return result;
}

} // namespace modelnet
