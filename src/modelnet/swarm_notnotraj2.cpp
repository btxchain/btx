// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotraj2.h>

#include <string>

namespace modelnet {

SwarmNotNoTraj2Result SwarmNoteNotNoTraj2(const SwarmNotNoTraj2& note, std::string& err)
{
    SwarmNotNoTraj2Result result;
    result.learned = false;
    result.bytes_moved = false;
    // An unstored trajectory learns nothing.
    if (note.traj_id.empty()) {
        result.code = "TRAJ";
        result.learned = false;
        result.bytes_moved = false;
        err = "TRAJ";
        return result;
    }
    if (!note.stored) {
        result.code = "NOT_LEARNED";
        result.learned = false;
        result.bytes_moved = false;
        err = "NOT_LEARNED";
        return result;
    }
    if (note.want_learn) {
        result.code = "HELD";
        result.learned = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.learned = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
