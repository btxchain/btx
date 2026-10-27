// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoforkavg.h>

#include <string>

namespace modelnet {

SwarmNotNoForkAvgResult SwarmNoteNotNoForkAvg(const SwarmNotNoForkAvg& note, std::string& err)
{
    SwarmNotNoForkAvgResult result;
    result.averaged = false;
    result.bytes_moved = false;
    // An incompatible branch forks instead of being averaged, and this note averages nothing.
    if (note.branch_id.empty()) {
        result.code = "BRANCH";
        result.averaged = false;
        result.bytes_moved = false;
        err = "BRANCH";
        return result;
    }
    if (note.incompatible) {
        result.code = "FORK";
        result.averaged = false;
        result.bytes_moved = false;
        err = "FORK";
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
