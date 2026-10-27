// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agents/builtin.h>

#include <string>

namespace modelnet {

bool SwarmAgentRunHold(SwarmAgentBuiltinResult& out, std::string& err)
{
    out = SwarmAgentBuiltinResult{};
    out.ran = true;
    out.launched = false;
    out.has_result = true;
    out.step = 0;
    out.result_hash = "hold";
    err.clear();
    return true;
}

} // namespace modelnet
