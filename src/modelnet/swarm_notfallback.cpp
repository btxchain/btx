// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfallback.h>

namespace modelnet {

SwarmNotFallbackResult SwarmNoteNotFallback(const SwarmNotFallback& note, std::string& err)
{
    SwarmNotFallbackResult result;
    result.observer_kept = false;
    result.training = false;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.observer_kept = false;
        result.training = false;
        err = "NODE";
        return result;
    }
    // A missing GPU still keeps the observer. Training is never started.
    if (note.want_train) {
        result.code = "CPU_ONLY";
        result.observer_kept = true;
        result.training = false;
        err = "CPU_ONLY";
        return result;
    }
    if (note.want_observe) {
        result.code = "NOTED";
        result.observer_kept = true;
        result.training = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.observer_kept = true;
    result.training = false;
    err.clear();
    return result;
}

} // namespace modelnet
