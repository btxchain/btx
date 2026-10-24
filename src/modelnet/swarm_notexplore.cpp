// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notexplore.h>

#include <string>

namespace modelnet {

SwarmNotExploreResult SwarmNoteNotExplore(const SwarmNotExplore& note, std::string& err)
{
    SwarmNotExploreResult result;
    result.assigned = false;
    result.candidates = 0;
    // An exploration illustration does not assign work.
    if (note.slot_id.empty()) {
        result.code = "SLOT";
        result.assigned = false;
        result.candidates = 0;
        err = "SLOT";
        return result;
    }
    if (note.want_assign) {
        result.code = "NOT_ASSIGNED";
        result.assigned = false;
        result.candidates = 0;
        err = "NOT_ASSIGNED";
        return result;
    }
    result.code = "NOTED";
    result.assigned = false;
    result.candidates = 0;
    err.clear();
    return result;
}

} // namespace modelnet
