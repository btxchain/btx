// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotraj.h>

#include <string>

namespace modelnet {

SwarmNotNoTrajResult SwarmNoteNotNoTraj(const SwarmNotNoTraj& note, std::string& err)
{
    SwarmNotNoTrajResult result;
    result.trained = false;
    result.bytes_moved = false;
    // A stored trajectory is not a training run.
    if (note.traj_id.empty()) {
        result.code = "TRAJ";
        result.trained = false;
        result.bytes_moved = false;
        err = "TRAJ";
        return result;
    }
    if (note.want_train) {
        result.code = "NOT_TRAIN";
        result.trained = false;
        result.bytes_moved = false;
        err = "NOT_TRAIN";
        return result;
    }
    result.code = "NOTED";
    result.trained = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
