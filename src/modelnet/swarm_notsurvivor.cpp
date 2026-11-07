// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notsurvivor.h>

#include <string>

namespace modelnet {

SwarmNotSurvivorResult SwarmNoteNotSurvivor(const SwarmNotSurvivor& note, std::string& err)
{
    SwarmNotSurvivorResult result;
    result.continued = false;
    // A survivor continuing after the original coordinator permanently disappears has not been shown.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.continued = false;
        err = "NODE";
        return result;
    }
    if (note.want_continue) {
        result.code = "NOT_SHOWN";
        result.continued = false;
        err = "NOT_SHOWN";
        return result;
    }
    result.code = "NOTED";
    result.continued = false;
    err.clear();
    return result;
}

} // namespace modelnet
