// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_maxsteps.h>

#include <cstdint>

namespace modelnet {

SwarmMaxStepsResult SwarmNoteMaxSteps(const SwarmMaxSteps& note, std::string& err)
{
    SwarmMaxStepsResult result;
    result.training = false;
    if (note.node_id.empty() || note.max_steps < 0) {
        result.code = "STEPS";
        result.training = false;
        err = "STEPS";
        return result;
    }
    // Zero max steps means training stays off. This wins even when
    // want_train is true. This note does not start training.
    if (note.max_steps == 0) {
        result.code = "CPU_ONLY";
        result.training = false;
        err = "CPU_ONLY";
        return result;
    }
    // This note does not start training.
    if (note.want_train) {
        result.code = "HELD";
        result.training = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.training = false;
    err.clear();
    return result;
}

} // namespace modelnet
