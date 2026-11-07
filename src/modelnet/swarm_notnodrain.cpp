// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodrain.h>

#include <string>

namespace modelnet {

SwarmNotNoDrainResult SwarmNoteNotNoDrain(const SwarmNotNoDrain& note, std::string& err)
{
    SwarmNotNoDrainResult result;
    result.running = false;
    result.workers = 0;
    // A governor drain starts no workers.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.running = false;
        result.workers = 0;
        err = "NODE";
        return result;
    }
    if (note.idle_off || note.battery || note.thermal || note.metered) {
        result.code = "DRAINED";
        result.running = false;
        result.workers = 0;
        err = "DRAINED";
        return result;
    }
    if (note.want_run) {
        result.code = "NOT_RUN";
        result.running = false;
        result.workers = 0;
        err = "NOT_RUN";
        return result;
    }
    result.code = "NOTED";
    result.running = false;
    result.workers = 0;
    err.clear();
    return result;
}

} // namespace modelnet
