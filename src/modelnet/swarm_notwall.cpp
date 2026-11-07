// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notwall.h>

namespace modelnet {

SwarmNotWallResult SwarmNoteNotWall(const SwarmNotWall& note, std::string& err)
{
    // published, recovered, and seconds stay false/zero on every branch.
    // This note does not claim a process was killed.
    SwarmNotWallResult result;
    result.published = false;
    result.recovered = false;
    result.seconds = 0;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.published = false;
        result.recovered = false;
        result.seconds = 0;
        err = "NODE";
        return result;
    }
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.recovered = false;
        result.seconds = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.recovered = false;
    result.seconds = 0;
    err.clear();
    return result;
}

} // namespace modelnet
