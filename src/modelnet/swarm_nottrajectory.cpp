// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nottrajectory.h>

#include <string>

namespace modelnet {

SwarmNotTrajectoryResult SwarmNoteNotTrajectory(const SwarmNotTrajectory& note, std::string& err)
{
    SwarmNotTrajectoryResult result;
    result.recorded = false;
    if (note.agent_id.empty()) {
        result.code = "AGENT";
        result.recorded = false;
        err = "AGENT";
        return result;
    }
    // No authorized public or synthetic trajectory has been generated from a running agent.
    if (note.want_record) {
        result.code = "NOT_RECORDED";
        result.recorded = false;
        err = "NOT_RECORDED";
        return result;
    }
    result.code = "NOTED";
    result.recorded = false;
    err.clear();
    return result;
}

} // namespace modelnet
