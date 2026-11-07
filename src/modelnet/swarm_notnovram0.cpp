// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnovram0.h>

#include <string>

namespace modelnet {

SwarmNotNoVram0Result SwarmNoteNotNoVram0(const SwarmNotNoVram0& note, std::string& err)
{
    // Without a device file VRAM stays zero. This note does not open one.
    SwarmNotNoVram0Result result;
    result.granted = false;
    result.bytes = 0;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.granted = false;
        result.bytes = 0;
        err = "NODE";
        return result;
    }
    // no_device is ZERO even when want_vram is false.
    if (note.no_device) {
        result.code = "ZERO";
        result.granted = false;
        result.bytes = 0;
        err = "ZERO";
        return result;
    }
    if (note.want_vram) {
        result.code = "ZERO";
        result.granted = false;
        result.bytes = 0;
        err = "ZERO";
        return result;
    }
    result.code = "NOTED";
    result.granted = false;
    result.bytes = 0;
    err.clear();
    return result;
}

} // namespace modelnet
