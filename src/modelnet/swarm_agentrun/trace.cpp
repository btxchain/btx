// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentrun/trace.h>

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

void SwarmAgentRunTrace::Append(const std::string& event)
{
    if (event.empty()) {
        return;
    }
    m_events.push_back(event);
}

std::vector<std::string> SwarmAgentRunTrace::events() const
{
    return m_events;
}

std::size_t SwarmAgentRunTrace::size() const
{
    return m_events.size();
}

} // namespace modelnet
