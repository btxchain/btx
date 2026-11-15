// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_readfence/warm.h>

namespace modelnet {

bool SwarmReadWarm::noted(const std::string& page) const
{
    return m_pages.find(page) != m_pages.end();
}

std::size_t SwarmReadWarm::size() const
{
    return m_pages.size();
}

bool SwarmReadWarm::Note(const std::string& page)
{
    m_pages.insert(page);
    return true;
}

} // namespace modelnet
