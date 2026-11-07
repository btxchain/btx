// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_promotegate/memory.h>

namespace modelnet {

void SwarmPromoteMemory::remember(const std::string& id)
{
    if (id.empty()) return;
    m_previous = id;
}

void SwarmPromoteMemory::clear()
{
    m_previous.clear();
}

} // namespace modelnet
