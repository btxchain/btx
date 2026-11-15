// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoglobal.h>

namespace modelnet {

SwarmNotNoGlobalResult SwarmNoteNotNoGlobal(const SwarmNotNoGlobal& note, std::string& err)
{
    SwarmNotNoGlobalResult result;
    result.built = false;
    result.bytes_moved = false;
    if (note.island_id.empty()) {
        result.code = "ISLAND";
        err = "ISLAND";
        return result;
    }
    if (note.want_build) {
        result.code = "NOT_BUILT";
        err = "NOT_BUILT";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
