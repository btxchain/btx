// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofork2.h>

#include <string>

namespace modelnet {

SwarmNotNoFork2Result SwarmNoteNotNoFork2(const SwarmNotNoFork2& note, std::string& err)
{
    SwarmNotNoFork2Result result;
    result.averaged = false;
    result.bytes_moved = false;
    // Incompatible branches fork instead of being averaged.
    if (note.branch_id.empty()) {
        result.code = "BRANCH";
        result.averaged = false;
        result.bytes_moved = false;
        err = "BRANCH";
        return result;
    }
    if (note.incompatible) {
        result.code = "FORKED";
        result.averaged = false;
        result.bytes_moved = false;
        err = "FORKED";
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
