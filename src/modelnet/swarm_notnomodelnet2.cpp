// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomodelnet2.h>

#include <string>

namespace modelnet {

SwarmNotNoModelNet2Result SwarmNoteNotNoModelNet2(const SwarmNotNoModelNet2& note, std::string& err)
{
    SwarmNotNoModelNet2Result result;
    result.disabled = false;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.disabled = false;
        err = "NODE";
        return result;
    }
    // ModelNet stays on by default. This note does not turn it off.
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
