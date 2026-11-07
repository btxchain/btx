// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnozero.h>

#include <string>

namespace modelnet {

SwarmNotNoZeroResult SwarmNoteNotNoZero(const SwarmNotNoZero& note, std::string& err)
{
    SwarmNotNoZeroResult result;
    result.training = false;
    result.applied_steps = 0;
    // Zero max steps stays CPU-only and this note trains nothing.
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.training = false;
        result.applied_steps = 0;
        err = "RUN";
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
