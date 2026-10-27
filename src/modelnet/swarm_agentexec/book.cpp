// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentexec/book.h>

#include <modelnet/swarm_agentexec/prefix.h>

#include <string>
#include <vector>

namespace modelnet {

bool SwarmAgentExecBook::Contains(const std::string& prefix) const
{
    for (const std::string& held : m_prefixes) {
        if (held == prefix) {
            return true;
        }
    }
    return false;
}

bool SwarmAgentExecBook::Add(const std::string& prefix)
{
    if (prefix.empty() || Contains(prefix)) {
        return false;
    }
    m_prefixes.push_back(prefix);
    return true;
}

bool SwarmAgentExecBook::Allows(const std::string& path) const
{
    for (const std::string& prefix : m_prefixes) {
        if (SwarmAgentExecBeginsWith(prefix, path)) {
            return true;
        }
    }
    return false;
}

} // namespace modelnet
