// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_vram.h>

#include <cstdint>

namespace modelnet {

SwarmVramTrainResult SwarmNoteVramTrain(const SwarmVramTrain& train, std::string& err)
{
    SwarmVramTrainResult result;
    result.training = false;
    if (train.node_id.empty() || train.vram_mib < 0) {
        result.training = false;
        result.code = "VRAM";
        err = "VRAM";
        return result;
    }
    // Zero VRAM or a missing training grant is not a trainer.
    // This wins even when the other of those two is true.
    if (train.want_train && (train.vram_mib == 0 || !train.license_allows_training)) {
        result.training = false;
        result.code = "CPU_ONLY";
        err = "CPU_ONLY";
        return result;
    }
    // This note does not start training even when VRAM and a license
    // are present. Nothing is launched.
    if (train.want_train) {
        result.training = false;
        result.code = "HELD";
        err.clear();
        return result;
    }
    result.training = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
