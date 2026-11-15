// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoneigh.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoNeighResult SwarmNoteNotNoNeigh(const SwarmNotNoNeigh& note, std::string& err)
{
    SwarmNotNoNeighResult result;
    result.connected = false;
    result.applied = 0;
    // A neighborhood is at most 4 lowest-RTT peers plus 2 new trust domains, and this note connects nothing.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.connected = false;
        result.applied = 0;
        err = "NODE";
        return result;
    }
    if (note.lowest_rtt > 4 || note.new_domains > 2) {
        result.code = "CAPPED";
        result.connected = false;
        result.applied = 0;
        err = "CAPPED";
        return result;
    }
    if (note.want_connect) {
        result.code = "CAPPED";
        result.connected = false;
        result.applied = 0;
        err = "CAPPED";
        return result;
    }
    result.code = "NOTED";
    result.connected = false;
    result.applied = 0;
    err.clear();
    return result;
}

} // namespace modelnet
