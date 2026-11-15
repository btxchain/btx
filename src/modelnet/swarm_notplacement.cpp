// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notplacement.h>

namespace modelnet {

SwarmNotPlacementResult SwarmNoteNotPlacement(const SwarmNotPlacement& note, std::string& err)
{
    SwarmNotPlacementResult result;
    result.placed = false;
    result.bytes_moved = false;
    if (note.page_id.empty()) {
        result.code = "PAGE";
        result.placed = false;
        result.bytes_moved = false;
        err = "PAGE";
        return result;
    }
    if (note.want_place) {
        result.code = "HELD";
        result.placed = false;
        result.bytes_moved = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.placed = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
