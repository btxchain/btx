// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcpueval.h>

#include <string>

namespace modelnet {

SwarmNotCpuEvalResult SwarmNoteNotCpuEval(const SwarmNotCpuEval& note, std::string& err)
{
    SwarmNotCpuEvalResult result;
    result.gpu_training = false;
    result.evaluated = false;
    // The default without device.json is public seeding and CPU evaluation.
    // GPU training stays off. This note launches nothing.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.gpu_training = false;
        result.evaluated = false;
        err = "NODE";
        return result;
    }
    // An absent device is CPU_EVAL even when want_gpu is false.
    if (!note.device_present) {
        result.code = "CPU_EVAL";
        result.gpu_training = false;
        result.evaluated = false;
        err = "CPU_EVAL";
        return result;
    }
    // This note launches nothing. GPU training stays off.
    if (note.want_gpu) {
        result.code = "CPU_EVAL";
        result.gpu_training = false;
        result.evaluated = false;
        err = "CPU_EVAL";
        return result;
    }
    result.code = "NOTED";
    result.gpu_training = false;
    result.evaluated = false;
    err.clear();
    return result;
}

} // namespace modelnet
