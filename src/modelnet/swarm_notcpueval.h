// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTCPUEVAL_H
#define BTX_MODELNET_SWARM_NOTCPUEVAL_H

#include <string>

namespace modelnet {

/**
 * A local note about CPU evaluation on one node. device_present records
 * whether a device is on the platform. want_gpu asks this note to train
 * on a GPU.
 *
 * The default without device.json is public seeding and CPU evaluation.
 * GPU training stays off. This note launches nothing. gpu_training and
 * evaluated stay false on every path.
 */
struct SwarmNotCpuEval {
    std::string node_id;
    bool device_present{false};
    bool want_gpu{false};
};

/**
 * Outcome of noting a CPU evaluation claim. gpu_training and evaluated
 * stay false on every path. GPU training stays off. This note launches
 * nothing.
 */
struct SwarmNotCpuEvalResult {
    std::string code;
    bool gpu_training{false};
    bool evaluated{false};
};

/**
 * Note a CPU evaluation claim without launching GPU training.
 * Order, first match wins:
 * 1. An empty node_id is NODE. gpu_training stays false, evaluated stays
 *    false, and err is NODE.
 * 2. If device_present is false, the note is CPU_EVAL even when want_gpu
 *    is false. gpu_training stays false, evaluated stays false, and err
 *    is CPU_EVAL.
 * 3. want_gpu is CPU_EVAL. gpu_training stays false, evaluated stays
 *    false, and err is CPU_EVAL.
 * 4. Otherwise the note is NOTED and err is cleared. gpu_training stays
 *    false and evaluated stays false.
 * gpu_training and evaluated stay false on every path. The default
 * without device.json is public seeding and CPU evaluation. GPU training
 * stays off. This note launches nothing.
 */
SwarmNotCpuEvalResult SwarmNoteNotCpuEval(const SwarmNotCpuEval& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTCPUEVAL_H
