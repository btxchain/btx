// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cachepair/book.h>

namespace modelnet {

bool SwarmCachePairBook::contains(const std::string& page) const
{
    if (page.empty()) return false;
    return m_shares.find(page) != m_shares.end();
}

std::size_t SwarmCachePairBook::size() const
{
    return m_shares.size();
}

std::vector<std::string> SwarmCachePairBook::members_of(const std::string& page) const
{
    const auto found = m_shares.find(page);
    if (found == m_shares.end()) return {};
    return found->second.members;
}

bool SwarmCachePairBook::store(const std::string& page, const std::vector<std::string>& members)
{
    if (contains(page)) return false;
    const SwarmCachePairRecord record = SwarmCachePairMakeRecord(page, members);
    if (!SwarmCachePairRecordUsable(record)) return false;
    m_shares.emplace(page, record);
    return true;
}

} // namespace modelnet
