// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoavgfork.h>

#include <string>

namespace modelnet {

SwarmNotNoAvgForkResult SwarmNoteNotNoAvgFork(const SwarmNotNoAvgFork& note, std::string& err)
{
    SwarmNotNoAvgForkResult result;
    result.averaged = false;
    result.forked = false;
    // An incompatible branch is not averaged. This note does not fork a
    // tree and does not move weights.
    if (note.branch_id.empty()) {
        result.code = "BRANCH";
        result.averaged = false;
        result.forked = false;
        err = "BRANCH";
        return result;
    }
    if (!note.compatible) {
        result.code = "FORK";
        result.averaged = false;
        result.forked = false;
        err = "FORK";
        return result;
    }
    if (note.want_average) {
        result.code = "FORK";
        result.averaged = false;
        result.forked = false;
        err = "FORK";
        return result;
    }
    result.code = "NOTED";
    result.averaged = false;
    result.forked = false;
    err.clear();
    return result;
}

} // namespace modelnet
