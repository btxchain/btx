// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnojoinon.h>

#include <string>

namespace modelnet {

SwarmNotNoJoinOnResult SwarmNoteNotNoJoinOn(const SwarmNotNoJoinOn& note, std::string& err)
{
    SwarmNotNoJoinOnResult result;
    result.disabled = false;
    result.joined = false;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.disabled = false;
        result.joined = false;
        err = "NODE";
        return result;
    }
    // Join-on-acquire stays the ModelNet-on default. This note does not disable it.
    if (note.want_disable) {
        result.code = "HELD";
        result.disabled = false;
        result.joined = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.disabled = false;
    result.joined = false;
    err.clear();
    return result;
}

} // namespace modelnet
