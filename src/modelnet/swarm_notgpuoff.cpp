// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notgpuoff.h>

#include <string>

namespace modelnet {

SwarmNotGpuOffResult SwarmNoteNotGpuOff(const SwarmNotGpuOff& note, std::string& err)
{
    SwarmNotGpuOffResult result;
    result.training = false;
    result.checkpoint_saved = false;
    // GPU training stays off by default. This note saves no checkpoint.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.training = false;
        result.checkpoint_saved = false;
        err = "NODE";
        return result;
    }
    if (note.want_train) {
        result.code = "GPU_OFF";
        result.training = false;
        result.checkpoint_saved = false;
        err = "GPU_OFF";
        return result;
    }
    result.code = "NOTED";
    result.training = false;
    result.checkpoint_saved = false;
    err.clear();
    return result;
}

} // namespace modelnet
