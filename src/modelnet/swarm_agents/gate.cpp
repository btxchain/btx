// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agents/gate.h>

#include <modelnet/swarm_agents/codes.h>
#include <modelnet/swarm_agents/limits.h>
#include <modelnet/swarm_agents/path_check.h>

#include <string>

namespace modelnet {

bool SwarmAgentGate::Admit(const SwarmAgentRunRequest& request, std::string& err) const
{
    if (request.network) {
        err = kAgentNetwork;
        return false;
    }
    if (request.host_interpreter) {
        err = kAgentHost;
        return false;
    }
    if (request.requested_threads < 0 || request.requested_threads > kAgentThreadCap ||
        request.requested_mib < 0 || request.requested_mib > kAgentMemoryCapMib) {
        err = kAgentCapped;
        return false;
    }
    if (!SwarmAgentPathInside(request.sandbox_root, request.path)) {
        err = kAgentEscape;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
