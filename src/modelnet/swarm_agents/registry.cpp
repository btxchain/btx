// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agents/registry.h>

#include <modelnet/swarm_agents/builtin.h>
#include <modelnet/swarm_agents/codes.h>

#include <string>

namespace modelnet {

bool SwarmAgentRegistry::Run(const std::string& kind, SwarmAgentBuiltinResult& out, std::string& err) const
{
    out = SwarmAgentBuiltinResult{};
    out.launched = false;
    if (kind == kAgentKindHold) {
        return SwarmAgentRunHold(out, err);
    }
    if (kind == kAgentKindIntegerStep) {
        return SwarmAgentRunIntegerStep(out, err);
    }
    err = kAgentUnknown;
    return false;
}

} // namespace modelnet
