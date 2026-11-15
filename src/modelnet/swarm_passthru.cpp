// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_passthru.h>

namespace modelnet {

SwarmPassthruResult SwarmNotePassthru(const SwarmPassthru& node, std::string& err)
{
    // GPU passthrough is not started.
    SwarmPassthruResult result;
    result.started = false;
    if (node.node_id.empty()) {
        result.code = "NODE";
        err = "NODE";
        return result;
    }
    if (node.want_start) {
        result.code = "NOT_STARTED";
        err = "NOT_STARTED";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
