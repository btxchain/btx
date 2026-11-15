// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocoord.h>

#include <string>

namespace modelnet {

SwarmNotNoCoordResult SwarmNoteNotNoCoord(const SwarmNotNoCoord& note, std::string& err)
{
    SwarmNotNoCoordResult result;
    result.skipped = false;
    result.joined = false;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.skipped = false;
        result.joined = false;
        err = "NODE";
        return result;
    }
    // Turning a coordinator off does not skip join. A note with the
    // coordinator off is HELD even when want_skip is false.
    if (!note.coordinator_on) {
        result.code = "HELD";
        result.skipped = false;
        result.joined = false;
        err = "HELD";
        return result;
    }
    // This note does not skip the join.
    if (note.want_skip) {
        result.code = "HELD";
        result.skipped = false;
        result.joined = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.skipped = false;
    result.joined = false;
    err.clear();
    return result;
}

} // namespace modelnet
