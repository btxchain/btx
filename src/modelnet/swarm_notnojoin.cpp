// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnojoin.h>

#include <string>

namespace modelnet {

SwarmNotNoJoinResult SwarmNoteNotNoJoin(const SwarmNotNoJoin& note, std::string& err)
{
    SwarmNotNoJoinResult result;
    result.skipped = false;
    result.joined = false;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.skipped = false;
        result.joined = false;
        err = "NODE";
        return result;
    }
    // Join-on-acquire stays the ModelNet-on default. A note with ModelNet
    // on is HELD even when want_skip is false.
    if (note.modelnet_on) {
        result.code = "HELD";
        result.skipped = false;
        result.joined = false;
        err = "HELD";
        return result;
    }
    // This note skips nothing.
    if (note.want_skip) {
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
