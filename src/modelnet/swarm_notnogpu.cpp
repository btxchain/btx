// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnogpu.h>

#include <string>

namespace modelnet {

SwarmNotNoGpuResult SwarmNoteNotNoGpu(const SwarmNotNoGpu& note, std::string& err)
{
    // Multi-GPU training has not run. One GPU step is the current hardware
    // bar and this note does not train.
    SwarmNotNoGpuResult result;
    result.trained = false;
    result.used = 0;
    if (note.step_id.empty()) {
        result.code = "STEP";
        result.trained = false;
        result.used = 0;
        err = "STEP";
        return result;
    }
    // A GPU count other than exactly one is NOT_RUN even when want_train is false.
    if (note.gpu_count != 1) {
        result.code = "NOT_RUN";
        result.trained = false;
        result.used = 0;
        err = "NOT_RUN";
        return result;
    }
    // This note does not train.
    if (note.want_train) {
        result.code = "NOT_RUN";
        result.trained = false;
        result.used = 0;
        err = "NOT_RUN";
        return result;
    }
    result.code = "NOTED";
    result.trained = false;
    result.used = 0;
    err.clear();
    return result;
}

} // namespace modelnet
