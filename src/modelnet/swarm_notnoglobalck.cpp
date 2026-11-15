// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoglobalck.h>

namespace modelnet {

SwarmNotNoGlobalCkResult SwarmNoteNotNoGlobalCk(const SwarmNotNoGlobalCk& note, std::string& err)
{
    SwarmNotNoGlobalCkResult result;
    result.saved = false;
    result.bytes_moved = false;
    if (note.island_id.empty()) {
        result.code = "ISLAND";
        err = "ISLAND";
        return result;
    }
    if (note.want_checkpoint) {
        result.code = "NO_CHECKPOINT";
        err = "NO_CHECKPOINT";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
