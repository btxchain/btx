// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoslotsone2.h>

namespace modelnet {

SwarmNotNoSlotsOne2Result SwarmNoteNotNoSlotsOne2(const SwarmNotNoSlotsOne2& note, std::string& err)
{
    SwarmNotNoSlotsOne2Result result;
    result.raised = false;
    result.slots = 1;
    // Without a device file the slot count stays 1.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.raised = false;
        result.slots = 1;
        err = "NODE";
        return result;
    }
    if (note.no_device) {
        result.code = "SLOTS_ONE";
        result.raised = false;
        result.slots = 1;
        err = "SLOTS_ONE";
        return result;
    }
    if (note.want_raise) {
        result.code = "HELD";
        result.raised = false;
        result.slots = 1;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.raised = false;
    result.slots = 1;
    err.clear();
    return result;
}

} // namespace modelnet
