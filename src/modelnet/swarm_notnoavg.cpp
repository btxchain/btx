// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoavg.h>

#include <string>

namespace modelnet {

SwarmNotNoAvgResult SwarmNoteNotNoAvg(const SwarmNotNoAvg& note, std::string& err)
{
    SwarmNotNoAvgResult result;
    result.averaged = false;
    result.bytes_moved = false;
    // An incompatible branch is not averaged. This note does not move bytes.
    if (note.branch_id.empty()) {
        result.code = "BRANCH";
        result.averaged = false;
        result.bytes_moved = false;
        err = "BRANCH";
        return result;
    }
    if (!note.compatible) {
        result.code = "SEPARATE";
        result.averaged = false;
        result.bytes_moved = false;
        err = "SEPARATE";
        return result;
    }
    if (note.want_average) {
        result.code = "HELD";
        result.averaged = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.averaged = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
