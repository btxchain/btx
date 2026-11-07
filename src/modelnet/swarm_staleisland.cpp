// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_staleisland.h>

#include <string>

namespace modelnet {

SwarmStaleIslandResult SwarmNoteStaleIsland(const SwarmStaleIsland& island, std::string& err)
{
    SwarmStaleIslandResult result;
    result.admitted = false;
    // A stale island is not admitted.
    if (island.island_id.empty()) {
        result.code = "ISLAND";
        result.admitted = false;
        err = "ISLAND";
        return result;
    }
    if (island.stale) {
        result.code = "NOT_ADMITTED";
        result.admitted = false;
        err = "NOT_ADMITTED";
        return result;
    }
    if (island.want_admit) {
        result.code = "HELD";
        result.admitted = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.admitted = false;
    err.clear();
    return result;
}

} // namespace modelnet
