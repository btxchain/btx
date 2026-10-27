// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_capact/actions.h>

namespace modelnet {

bool SwarmCapActActions::contains(const std::string& name) const
{
    if (name.empty()) return false;
    return m_names.find(name) != m_names.end();
}

std::size_t SwarmCapActActions::size() const
{
    return m_names.size();
}

bool SwarmCapActActions::store(const std::string& name)
{
    if (contains(name)) return false;
    const SwarmCapActActionEntry entry = SwarmCapActMakeAction(name);
    if (!SwarmCapActActionUsable(entry)) return false;
    m_names.emplace(name, entry);
    return true;
}

} // namespace modelnet
