// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotrajectory.h>

#include <string>

namespace modelnet {

SwarmNotNoTrajectoryResult SwarmNoteNotNoTrajectory(const SwarmNotNoTrajectory& note, std::string& err)
{
    SwarmNotNoTrajectoryResult result;
    result.learned = false;
    result.trained = false;
    // An unstored trajectory learns nothing and trains nothing.
    if (note.traj_id.empty()) {
        result.code = "TRAJ";
        result.learned = false;
        result.trained = false;
        err = "TRAJ";
        return result;
    }
    if (note.unstored) {
        result.code = "NOT_STORED";
        result.learned = false;
        result.trained = false;
        err = "NOT_STORED";
        return result;
    }
    if (note.want_learn) {
        result.code = "HELD";
        result.learned = false;
        result.trained = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.learned = false;
    result.trained = false;
    err.clear();
    return result;
}

} // namespace modelnet
