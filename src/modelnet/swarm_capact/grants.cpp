// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_capact/grants.h>

namespace modelnet {

bool SwarmCapActGrants::contains(const std::string& name) const
{
    if (name.empty()) return false;
    return m_names.find(name) != m_names.end();
}

std::size_t SwarmCapActGrants::size() const
{
    return m_names.size();
}

bool SwarmCapActGrants::store(const std::string& name)
{
    if (contains(name)) return false;
    const SwarmCapActGrantRecord record = SwarmCapActMakeGrant(name);
    if (!SwarmCapActGrantUsable(record)) return false;
    m_names.emplace(name, record);
    return true;
}

} // namespace modelnet
