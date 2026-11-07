// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnovramzero2.h>

#include <string>

namespace modelnet {

SwarmNotNoVramZero2Result SwarmNoteNotNoVramZero2(const SwarmNotNoVramZero2& note, std::string& err)
{
    // Without a device file, VRAM stays zero.
    SwarmNotNoVramZero2Result result;
    result.claimed = false;
    result.vram_mib = 0;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.claimed = false;
        result.vram_mib = 0;
        err = "NODE";
        return result;
    }
    // no_device is VRAM_ZERO even when want_claim is false.
    if (note.no_device) {
        result.code = "VRAM_ZERO";
        result.claimed = false;
        result.vram_mib = 0;
        err = "VRAM_ZERO";
        return result;
    }
    if (note.want_claim) {
        result.code = "HELD";
        result.claimed = false;
        result.vram_mib = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.claimed = false;
    result.vram_mib = 0;
    err.clear();
    return result;
}

} // namespace modelnet
