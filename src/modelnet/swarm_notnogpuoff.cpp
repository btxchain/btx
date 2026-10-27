// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnogpuoff.h>

#include <string>

namespace modelnet {

SwarmNotNoGpuOffResult SwarmNoteNotNoGpuOff(const SwarmNotNoGpuOff& note, std::string& err)
{
    // Without device.json, GPU training stays off.
    SwarmNotNoGpuOffResult result;
    result.training = false;
    result.gpu = false;
    if (note.device_id.empty()) {
        result.code = "DEVICE";
        result.training = false;
        result.gpu = false;
        err = "DEVICE";
        return result;
    }
    // device_json false is NOT_RUN even when want_train is false.
    if (!note.device_json) {
        result.code = "NOT_RUN";
        result.training = false;
        result.gpu = false;
        err = "NOT_RUN";
        return result;
    }
    if (note.want_train) {
        result.code = "NOT_RUN";
        result.training = false;
        result.gpu = false;
        err = "NOT_RUN";
        return result;
    }
    result.code = "NOTED";
    result.training = false;
    result.gpu = false;
    err.clear();
    return result;
}

} // namespace modelnet
