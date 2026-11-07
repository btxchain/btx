// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_readfence/roster.h>

namespace modelnet {

bool SwarmReadRoster::revoked(const std::string& member) const
{
    return m_members.find(member) != m_members.end();
}

std::size_t SwarmReadRoster::size() const
{
    return m_members.size();
}

bool SwarmReadRoster::Revoke(const std::string& member)
{
    if (member.empty()) return false;
    const auto inserted = m_members.insert(member);
    return inserted.second;
}

} // namespace modelnet
