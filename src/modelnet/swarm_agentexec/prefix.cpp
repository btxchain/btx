// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentexec/prefix.h>

#include <string>

namespace modelnet {

bool SwarmAgentExecBeginsWith(const std::string& prefix, const std::string& path)
{
    if (prefix.empty()) {
        return false;
    }
    if (path.size() < prefix.size()) {
        return false;
    }
    return path.compare(0, prefix.size(), prefix) == 0;
}

} // namespace modelnet
