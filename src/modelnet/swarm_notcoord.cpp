// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcoord.h>

#include <string>

namespace modelnet {

SwarmNotCoordResult SwarmNoteNotCoord(const SwarmNotCoord& note, std::string& err)
{
    SwarmNotCoordResult result;
    result.ran = false;
    // Distinct agent tasks have not executed across a GPU node and a CPU node.
    if (note.task_id.empty()) {
        result.code = "TASK";
        result.ran = false;
        err = "TASK";
        return result;
    }
    if (note.want_run) {
        result.code = "NOT_RUN";
        result.ran = false;
        err = "NOT_RUN";
        return result;
    }
    result.code = "NOTED";
    result.ran = false;
    err.clear();
    return result;
}

} // namespace modelnet
