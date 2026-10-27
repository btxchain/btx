// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoslots.h>

namespace modelnet {

SwarmNotNoSlotsResult SwarmNoteNotNoSlots(const SwarmNotNoSlots& note, std::string& err)
{
    SwarmNotNoSlotsResult result;
    result.opened = false;
    result.applied = 0;
    // The default without a device file opens one slot and this note opens none.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.opened = false;
        result.applied = 0;
        err = "NODE";
        return result;
    }
    if (note.slots != 1) {
        result.code = "CAPPED";
        result.opened = false;
        result.applied = 0;
        err = "CAPPED";
        return result;
    }
    if (note.want_open) {
        result.code = "CAPPED";
        result.opened = false;
        result.applied = 0;
        err = "CAPPED";
        return result;
    }
    result.code = "NOTED";
    result.opened = false;
    result.applied = 0;
    err.clear();
    return result;
}

} // namespace modelnet
