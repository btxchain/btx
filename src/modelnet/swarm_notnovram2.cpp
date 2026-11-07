// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnovram2.h>

#include <string>

namespace modelnet {

SwarmNotNoVram2Result SwarmNoteNotNoVram2(const SwarmNotNoVram2& note, std::string& err)
{
    // Without a device file the node is CPU-only, VRAM stays zero, and
    // GPU training stays off. This note does not open a device file.
    SwarmNotNoVram2Result result;
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
