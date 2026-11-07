// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_readfence/book.h>

namespace modelnet {

bool SwarmReadBook::placed(const std::string& page) const
{
    return m_pages.find(page) != m_pages.end();
}

std::string SwarmReadBook::family(const std::string& page) const
{
    const auto it = m_pages.find(page);
    if (it == m_pages.end()) return {};
    return it->second.family();
}

std::size_t SwarmReadBook::size() const
{
    return m_pages.size();
}

bool SwarmReadBook::Place(const std::string& page, const std::string& family)
{
    SwarmReadPage row;
    if (!row.bind(page, family)) return false;
    m_pages.insert_or_assign(page, row);
    return true;
}

} // namespace modelnet
