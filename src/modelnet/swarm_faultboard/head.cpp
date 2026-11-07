// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultboard/head.h>

#include <string>

namespace modelnet {

bool SwarmFaultHeadBook::Keep(const std::string& channel, const std::string& head, std::string& err)
{
    m_heads[channel] = head;
    err.clear();
    return true;
}

std::string SwarmFaultHeadBook::head_for(const std::string& channel) const
{
    const auto found = m_heads.find(channel);
    if (found == m_heads.end()) {
        return {};
    }
    return found->second;
}

void SwarmFaultHeadBook::Restore(const std::string& channel, const std::string& previous)
{
    std::string from_head;
    const auto found = m_heads.find(channel);
    if (found != m_heads.end()) {
        from_head = found->second;
    }
    m_heads[channel] = previous;
    m_rollbacks.push_back(Rollback{channel, from_head, previous});
}

std::size_t SwarmFaultHeadBook::rollback_count() const
{
    return m_rollbacks.size();
}

} // namespace modelnet
