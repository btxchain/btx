// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notjoinon.h>

#include <string>

namespace modelnet {

SwarmNotJoinOnResult SwarmNoteNotJoinOn(const SwarmNotJoinOn& note, std::string& err)
{
    SwarmNotJoinOnResult result;
    result.skipped = false;
    result.joined = false;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.skipped = false;
        result.joined = false;
        err = "NODE";
        return result;
    }
    // Join-on-acquire is the ModelNet-on default. A note with ModelNet off
    // is DEFAULT_ON even when want_skip_join is false.
    if (!note.modelnet_on) {
        result.code = "DEFAULT_ON";
        result.skipped = false;
        result.joined = false;
        err = "DEFAULT_ON";
        return result;
    }
    // This note does not join a peer or skip the join.
    if (note.want_skip_join) {
        result.code = "HELD";
        result.skipped = false;
        result.joined = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.skipped = false;
    result.joined = false;
    err.clear();
    return result;
}

} // namespace modelnet
