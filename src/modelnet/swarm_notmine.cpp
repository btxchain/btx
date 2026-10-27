// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmine.h>

namespace modelnet {

SwarmNotMineResult SwarmNoteNotMine(const SwarmNotMine& note, std::string& err)
{
    SwarmNotMineResult result;
    result.mined = false;
    if (note.node_id.empty()) {
        result.code = "MINE";
        result.mined = false;
        err = "MINE";
        return result;
    }
    // Do not mine past the ExactReplay stall.
    if (note.want_mine) {
        result.code = "NOT_MINED";
        result.mined = false;
        err = "NOT_MINED";
        return result;
    }
    result.code = "NOTED";
    result.mined = false;
    err.clear();
    return result;
}

} // namespace modelnet
