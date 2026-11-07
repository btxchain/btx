// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notisland.h>

namespace modelnet {

SwarmNotIslandResult SwarmNoteNotIsland(const SwarmNotIsland& note, std::string& err)
{
    SwarmNotIslandResult result;
    result.published = false;
    result.averaged = false;
    result.bytes_moved = false;
    result.delta = 0;
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.published = false;
        result.averaged = false;
        result.bytes_moved = false;
        result.delta = 0;
        err = "RUN";
        return result;
    }
    // Independent training islands have not been compared, and weights are not averaged.
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.averaged = false;
        result.bytes_moved = false;
        result.delta = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.averaged = false;
    result.bytes_moved = false;
    result.delta = 0;
    err.clear();
    return result;
}

} // namespace modelnet
