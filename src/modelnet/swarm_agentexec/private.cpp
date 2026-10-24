// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentexec/private.h>

#include <modelnet/swarm_agentexec/limits.h>
#include <modelnet/swarm_agentexec/prefix.h>

#include <string>

namespace modelnet {

bool SwarmAgentExecPrivatePath(const std::string& path)
{
    return SwarmAgentExecBeginsWith(kSwarmAgentExecPrivatePrefix, path);
}

} // namespace modelnet
