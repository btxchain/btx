// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofork.h>

#include <string>

namespace modelnet {

SwarmNotNoForkResult SwarmNoteNotNoFork(const SwarmNotNoFork& note, std::string& err)
{
    SwarmNotNoForkResult result;
    result.merged = false;
    result.bytes_moved = false;
    // Incompatible branches fork instead of being merged, and this note merges nothing.
    if (note.branch_id.empty()) {
        result.code = "BRANCH";
        result.merged = false;
        result.bytes_moved = false;
        err = "BRANCH";
        return result;
    }
    if (!note.compatible) {
        result.code = "FORK";
        result.merged = false;
        result.bytes_moved = false;
        err = "FORK";
        return result;
    }
    if (note.want_merge) {
        result.code = "FORK";
        result.merged = false;
        result.bytes_moved = false;
        err = "FORK";
        return result;
    }
    result.code = "NOTED";
    result.merged = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
