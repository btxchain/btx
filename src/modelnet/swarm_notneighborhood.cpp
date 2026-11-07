// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notneighborhood.h>

namespace modelnet {

SwarmNotNeighborhoodResult SwarmNoteNotNeighborhood(const SwarmNotNeighborhood& note, std::string& err)
{
    // This note does not connect peers. The neighborhood cap is 4 lowest-RTT plus 2 new trust domains, and this note does not select them.
    SwarmNotNeighborhoodResult result;
    result.connected = false;
    result.chosen = 0;
    if (note.node_id.empty()) {
        result.code = "NODE";
        err = "NODE";
        return result;
    }
    if (note.peer_count > 6 || note.want_connect) {
        result.code = "CAPPED";
        err = "CAPPED";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
