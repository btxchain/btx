// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnovram.h>

#include <string>

namespace modelnet {

SwarmNotNoVramResult SwarmNoteNotNoVram(const SwarmNotNoVram& note, std::string& err)
{
    SwarmNotNoVramResult result;
    result.claimed = false;
    result.mib = 0;
    // A missing device file claims no VRAM. This note does not open one.
    if (note.device_id.empty()) {
        result.code = "DEVICE";
        result.claimed = false;
        result.mib = 0;
        err = "DEVICE";
        return result;
    }
    if (note.vram_mib != 0) {
        result.code = "UNMEASURED";
        result.claimed = false;
        result.mib = 0;
        err = "UNMEASURED";
        return result;
    }
    if (note.want_claim) {
        result.code = "UNMEASURED";
        result.claimed = false;
        result.mib = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.claimed = false;
    result.mib = 0;
    err.clear();
    return result;
}

} // namespace modelnet
