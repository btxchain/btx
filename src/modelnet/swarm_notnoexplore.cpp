// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoexplore.h>

#include <string>

namespace modelnet {

SwarmNotNoExploreResult SwarmNoteNotNoExplore(const SwarmNotNoExplore& note, std::string& err)
{
    SwarmNotNoExploreResult result;
    result.assigned = false;
    result.slots = 0;
    // An exploration illustration assigns no worker.
    if (note.slot_id.empty()) {
        result.code = "SLOT";
        result.assigned = false;
        result.slots = 0;
        err = "SLOT";
        return result;
    }
    if (note.want_assign) {
        result.code = "NOT_ASSIGNED";
        result.assigned = false;
        result.slots = 0;
        err = "NOT_ASSIGNED";
        return result;
    }
    result.code = "NOTED";
    result.assigned = false;
    result.slots = 0;
    err.clear();
    return result;
}

} // namespace modelnet
