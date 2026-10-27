// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoneighcap2.h>

#include <string>

namespace modelnet {

SwarmNotNoNeighCap2Result SwarmNoteNotNoNeighCap2(const SwarmNotNoNeighCap2& note, std::string& err)
{
    SwarmNotNoNeighCap2Result result;
    result.raised = false;
    // A neighborhood stays four lowest-RTT peers plus two new trust domains and this note raises nothing.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.raised = false;
        err = "NODE";
        return result;
    }
    if (note.low_rtt > 4 || note.extra_domains > 2) {
        result.code = "CAPPED";
        result.raised = false;
        err = "CAPPED";
        return result;
    }
    if (note.want_raise) {
        result.code = "CAPPED";
        result.raised = false;
        err = "CAPPED";
        return result;
    }
    result.code = "NOTED";
    result.raised = false;
    err.clear();
    return result;
}

} // namespace modelnet
