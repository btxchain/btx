// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_readfence/names.h>

#include <modelnet/swarm_readfence/limits.h>

namespace modelnet {

bool SwarmReadKnownEngine(const std::string& name)
{
    if (name.empty()) return false;
    for (const char* known : kSwarmReadEngineNames) {
        if (name == known) return true;
    }
    return false;
}

} // namespace modelnet
