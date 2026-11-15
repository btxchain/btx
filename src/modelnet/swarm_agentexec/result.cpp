// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentexec/result.h>

#include <string>

namespace modelnet {

void SwarmAgentExecResult::Store(const std::string& digest)
{
    m_digest = digest;
    m_ran = true;
}

bool SwarmAgentExecResult::ran() const
{
    return m_ran;
}

std::string SwarmAgentExecResult::result() const
{
    return m_digest;
}

} // namespace modelnet
