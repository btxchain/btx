// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodevice2.h>

#include <string>

namespace modelnet {

SwarmNotNoDevice2Result SwarmNoteNotNoDevice2(const SwarmNotNoDevice2& note, std::string& err)
{
    // Without a device file the node stays CPU-only. This note does not
    // open a device file. gpu stays false and vram_mib stays 0 on every path.
    SwarmNotNoDevice2Result result;
    result.gpu = false;
    result.vram_mib = 0;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.gpu = false;
        result.vram_mib = 0;
        err = "NODE";
        return result;
    }
    // device_file false is CPU_ONLY even when want_gpu is false.
    if (!note.device_file) {
        result.code = "CPU_ONLY";
        result.gpu = false;
        result.vram_mib = 0;
        err = "CPU_ONLY";
        return result;
    }
    if (note.want_gpu) {
        result.code = "HELD";
        result.gpu = false;
        result.vram_mib = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.gpu = false;
    result.vram_mib = 0;
    err.clear();
    return result;
}

} // namespace modelnet
