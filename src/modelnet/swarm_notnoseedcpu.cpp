// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoseedcpu.h>

#include <string>

namespace modelnet {

SwarmNotNoSeedCpuResult SwarmNoteNotNoSeedCpu(const SwarmNotNoSeedCpu& note, std::string& err)
{
    // Without a device file the node seeds and evaluates on CPU and does
    // not train on a GPU.
    SwarmNotNoSeedCpuResult result;
    result.trained = false;
    result.gpu = false;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.trained = false;
        result.gpu = false;
        err = "NODE";
        return result;
    }
    // no_device is CPU_ONLY even when want_train is false.
    if (note.no_device) {
        result.code = "CPU_ONLY";
        result.trained = false;
        result.gpu = false;
        err = "CPU_ONLY";
        return result;
    }
    if (note.want_train) {
        result.code = "OFF";
        result.trained = false;
        result.gpu = false;
        err = "OFF";
        return result;
    }
    result.code = "NOTED";
    result.trained = false;
    result.gpu = false;
    err.clear();
    return result;
}

} // namespace modelnet
