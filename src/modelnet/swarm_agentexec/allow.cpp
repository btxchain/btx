// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentexec/allow.h>

#include <modelnet/swarm_agentexec/book.h>
#include <modelnet/swarm_agentexec/codes.h>

#include <string>

namespace modelnet {

bool SwarmAgentExecAllow(SwarmAgentExecBook& book, const std::string& prefix, std::string& err)
{
    if (prefix.empty()) {
        err = kSwarmAgentExecPath;
        return false;
    }
    if (!book.Add(prefix)) {
        err = kSwarmAgentExecReplay;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
