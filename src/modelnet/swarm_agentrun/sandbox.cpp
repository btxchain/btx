// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentrun/sandbox.h>

#include <modelnet/swarm_agentrun/codes.h>
#include <modelnet/swarm_agentrun/trace.h>

#include <string>

namespace modelnet {

bool SwarmAgentRunSandboxRefuse(SwarmAgentRunTrace& trace, std::string& err)
{
    err = kAgentRunSandboxAbsent;
    trace.Append(kAgentRunSandboxAbsent);
    return false;
}

} // namespace modelnet
