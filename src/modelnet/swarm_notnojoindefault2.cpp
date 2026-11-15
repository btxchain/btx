// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnojoindefault2.h>

#include <string>

namespace modelnet {

SwarmNotNoJoinDefault2Result SwarmNoteNotNoJoinDefault2(const SwarmNotNoJoinDefault2& note, std::string& err)
{
    SwarmNotNoJoinDefault2Result result;
    result.left = false;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.left = false;
        err = "NODE";
        return result;
    }
    // Join-on-acquire stays the ModelNet-on default.
    if (note.want_leave) {
        result.code = "HELD";
        result.left = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.left = false;
    err.clear();
    return result;
}

} // namespace modelnet
