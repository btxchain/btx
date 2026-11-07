// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTEXEC_TOOL_H
#define BITCOIN_MODELNET_SWARM_AGENTEXEC_TOOL_H

#include <string>

namespace modelnet {

/** How Execute treats a tool name before it decides to hash. */
enum class SwarmAgentExecToolKind {
    Empty,
    Net,
    Sha256,
    Other,
};

/**
 * Empty is Empty. "net" is Net. "sha256" is Sha256.
 * Any other byte string, including a different case, is Other.
 * The match is exact. No process is named or started.
 */
SwarmAgentExecToolKind SwarmAgentExecClassifyTool(const std::string& tool);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTEXEC_TOOL_H
