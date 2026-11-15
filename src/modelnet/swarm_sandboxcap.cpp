// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandboxcap.h>

namespace modelnet {

SwarmSandboxCapResult SwarmNoteSandboxCap(const SwarmSandboxCap& node, std::string& err)
{
    // A sandbox raise stays capped.
    SwarmSandboxCapResult result;
    result.raised = false;
    if (node.node_id.empty()) {
        result.code = "NODE";
        result.raised = false;
        err = "NODE";
        return result;
    }
    if (node.want_raise) {
        result.code = "CAPPED";
        result.raised = false;
        err = "CAPPED";
        return result;
    }
    result.code = "NOTED";
    result.raised = false;
    err.clear();
    return result;
}

} // namespace modelnet
