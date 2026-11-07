// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notslots.h>

#include <string>

namespace modelnet {

SwarmNotSlotsResult SwarmNoteNotSlots(const SwarmNotSlots& note, std::string& err)
{
    // The default without device.json is one slot. This note launches nothing.
    SwarmNotSlotsResult result;
    result.raised = false;
    result.applied_slots = 0;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.raised = false;
        result.applied_slots = 0;
        err = "NODE";
        return result;
    }
    // A slot count other than exactly one is CAPPED even when want_raise is false.
    if (note.slot_count != 1) {
        result.code = "CAPPED";
        result.raised = false;
        result.applied_slots = 0;
        err = "CAPPED";
        return result;
    }
    // This note launches nothing.
    if (note.want_raise) {
        result.code = "CAPPED";
        result.raised = false;
        result.applied_slots = 0;
        err = "CAPPED";
        return result;
    }
    result.code = "NOTED";
    result.raised = false;
    result.applied_slots = 0;
    err.clear();
    return result;
}

} // namespace modelnet
