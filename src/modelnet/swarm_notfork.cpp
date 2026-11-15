// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfork.h>

#include <string>

namespace modelnet {

SwarmNotForkResult SwarmNoteNotFork(const SwarmNotFork& note, std::string& err)
{
    SwarmNotForkResult result;
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
    if (!note.compatible) {
        result.code = "FORK";
        result.averaged = false;
        result.bytes_moved = false;
        err = "FORK";
        return result;
    }
    if (note.want_average) {
        result.code = "FORK";
        result.averaged = false;
        result.bytes_moved = false;
        err = "FORK";
        return result;
    }
    result.code = "NOTED";
    result.averaged = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
