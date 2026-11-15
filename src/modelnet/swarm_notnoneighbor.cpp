// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoneighbor.h>

namespace modelnet {

SwarmNotNoNeighborResult SwarmNoteNotNoNeighbor(const SwarmNotNoNeighbor& note, std::string& err)
{
    // The neighborhood cap is 4 lowest-RTT peers plus 2 new trust domains.
    // This note connects none.
    SwarmNotNoNeighborResult result;
    result.expanded = false;
    result.connected = false;
    if (note.node_id.empty()) {
        result.code = "NODE";
        err = "NODE";
        return result;
    }
    if (note.low_rtt != 4 || note.new_domains != 2) {
        result.code = "CAPPED";
        err = "CAPPED";
        return result;
    }
    if (note.want_expand) {
        result.code = "CAPPED";
        err = "CAPPED";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
