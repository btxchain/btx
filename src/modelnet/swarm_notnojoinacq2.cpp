// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnojoinacq2.h>

#include <string>

namespace modelnet {

SwarmNotNoJoinAcq2Result SwarmNoteNotNoJoinAcq2(const SwarmNotNoJoinAcq2& note, std::string& err)
{
    SwarmNotNoJoinAcq2Result result;
    result.disabled = false;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.disabled = false;
        err = "NODE";
        return result;
    }
    // Join on acquire stays the ModelNet-on default. This note does not disable it.
    if (note.want_disable) {
        result.code = "HELD";
        result.disabled = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.disabled = false;
    err.clear();
    return result;
}

} // namespace modelnet
