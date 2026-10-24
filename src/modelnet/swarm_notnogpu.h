// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOGPU_H
#define BTX_MODELNET_SWARM_NOTNOGPU_H

#include <string>

namespace modelnet {

/**
 * A local note about one GPU step. want_train asks this note to train.
 *
 * Multi-GPU training has not run. One GPU step is the current hardware bar
 * and this note does not train. trained stays false and used stays 0 on
 * every path.
 */
struct SwarmNotNoGpu {
    std::string step_id;
    int gpu_count{0};
    bool want_train{false};
};

/**
 * Outcome of noting a GPU step. trained stays false and used stays 0 on
 * every path. Multi-GPU training has not run. One GPU step is the current
 * hardware bar and this note does not train.
 */
struct SwarmNotNoGpuResult {
    std::string code;
    bool trained{false};
    int used{0};
};

/**
 * Note a GPU step without training.
 * Order, first match wins: an empty step_id is STEP. If gpu_count is not
 * exactly 1, the note is NOT_RUN even when want_train is false. want_train
 * is NOT_RUN. Otherwise the note is NOTED and err is cleared. trained stays
 * false and used stays 0 on every path. Multi-GPU training has not run.
 * One GPU step is the current hardware bar and this note does not train.
 */
SwarmNotNoGpuResult SwarmNoteNotNoGpu(const SwarmNotNoGpu& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOGPU_H
