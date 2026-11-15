// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notstall.h>

#include <string>

namespace modelnet {

SwarmNotStallResult SwarmNoteNotStall(const SwarmNotStall& note, std::string& err)
{
    SwarmNotStallResult result;
    result.mined = false;
    result.passed_stall = false;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.mined = false;
        result.passed_stall = false;
        err = "NODE";
        return result;
    }
    // Mining does not pass the ExactReplay stall.
    if (note.want_mine) {
        result.code = "NOT_MINED";
        result.mined = false;
        result.passed_stall = false;
        err = "NOT_MINED";
        return result;
    }
    result.code = "NOTED";
    result.mined = false;
    result.passed_stall = false;
    err.clear();
    return result;
}

} // namespace modelnet
