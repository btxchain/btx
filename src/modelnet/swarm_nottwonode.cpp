// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nottwonode.h>

#include <string>

namespace modelnet {

SwarmNotTwoNodeResult SwarmNoteNotTwoNode(const SwarmNotTwoNode& note, std::string& err)
{
    SwarmNotTwoNodeResult result;
    result.paired = false;
    // Two-machine collaborative training is out of scope for this note.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.paired = false;
        err = "NODE";
        return result;
    }
    if (note.want_pair) {
        result.code = "OUT_OF_SCOPE";
        result.paired = false;
        err = "OUT_OF_SCOPE";
        return result;
    }
    result.code = "NOTED";
    result.paired = false;
    err.clear();
    return result;
}

} // namespace modelnet
