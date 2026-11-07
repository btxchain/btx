// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentexec/tool.h>

#include <modelnet/swarm_agentexec/limits.h>

#include <string>

namespace modelnet {

SwarmAgentExecToolKind SwarmAgentExecClassifyTool(const std::string& tool)
{
    if (tool.empty()) {
        return SwarmAgentExecToolKind::Empty;
    }
    if (tool == kSwarmAgentExecToolNet) {
        return SwarmAgentExecToolKind::Net;
    }
    if (tool == kSwarmAgentExecToolSha256) {
        return SwarmAgentExecToolKind::Sha256;
    }
    return SwarmAgentExecToolKind::Other;
}

} // namespace modelnet
