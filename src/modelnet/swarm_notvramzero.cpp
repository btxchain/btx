// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notvramzero.h>

#include <string>

namespace modelnet {

SwarmNotVramZeroResult SwarmNoteNotVramZero(const SwarmNotVramZero& note, std::string& err)
{
    SwarmNotVramZeroResult result;
    result.training = false;
    result.applied_vram = 0;
    // The default without device.json reports no VRAM and trains nothing from this note.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.training = false;
        result.applied_vram = 0;
        err = "NODE";
        return result;
    }
    if (note.vram_mib != 0) {
        result.code = "CPU_ONLY";
        result.training = false;
        result.applied_vram = 0;
        err = "CPU_ONLY";
        return result;
    }
    if (note.want_train) {
        result.code = "CPU_ONLY";
        result.training = false;
        result.applied_vram = 0;
        err = "CPU_ONLY";
        return result;
    }
    result.code = "NOTED";
    result.training = false;
    result.applied_vram = 0;
    err.clear();
    return result;
}

} // namespace modelnet
