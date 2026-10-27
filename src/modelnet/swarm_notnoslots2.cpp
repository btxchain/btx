// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoslots2.h>

#include <string>

namespace modelnet {

SwarmNotNoSlots2Result SwarmNoteNotNoSlots2(const SwarmNotNoSlots2& note, std::string& err)
{
    // Default slots stay 1. This note raises nothing.
    SwarmNotNoSlots2Result result;
    result.raised = false;
    result.slots = 0;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.raised = false;
        result.slots = 0;
        err = "NODE";
        return result;
    }
    if (note.want_raise) {
        result.code = "HELD";
        result.raised = false;
        result.slots = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.raised = false;
    result.slots = 0;
    err.clear();
    return result;
}

} // namespace modelnet
