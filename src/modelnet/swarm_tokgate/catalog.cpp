// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_tokgate/catalog.h>

#include <string>

namespace modelnet {

bool SwarmTokenGateEngineNameAllowed(const std::string& engine_name)
{
    if (engine_name.empty()) return false;
    if (engine_name == kSwarmTokenGateVllm) return true;
    if (engine_name == kSwarmTokenGateSglang) return true;
    if (engine_name == kSwarmTokenGateLmcache) return true;
    return false;
}

bool SwarmTokenGateEngineNameRuns(const std::string& engine_name)
{
    if (SwarmTokenGateEngineNameAllowed(engine_name)) return false;
    if (engine_name.empty()) return false;
    return false;
}

} // namespace modelnet
