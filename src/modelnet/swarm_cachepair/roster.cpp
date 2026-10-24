// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cachepair/roster.h>

#include <modelnet/swarm_cachepair/seat.h>

namespace modelnet {

bool SwarmCachePairRoster::known(const std::string& page) const
{
    if (page.empty()) return false;
    const auto found = m_pages.find(page);
    return found != m_pages.end() && !found->second.empty();
}

bool SwarmCachePairRoster::contains(const std::string& page, const std::string& member) const
{
    if (page.empty() || member.empty()) return false;
    const auto found = m_pages.find(page);
    if (found == m_pages.end()) return false;
    return found->second.find(member) != found->second.end();
}

std::size_t SwarmCachePairRoster::members(const std::string& page) const
{
    const auto found = m_pages.find(page);
    if (found == m_pages.end()) return 0;
    return found->second.size();
}

std::size_t SwarmCachePairRoster::pages() const
{
    return m_pages.size();
}

std::vector<std::string> SwarmCachePairRoster::list(const std::string& page) const
{
    std::vector<std::string> out;
    const auto found = m_pages.find(page);
    if (found == m_pages.end()) return out;
    out.assign(found->second.begin(), found->second.end());
    return out;
}

bool SwarmCachePairRoster::place(const std::string& page, const std::string& member)
{
    const SwarmCachePairSeat seat = SwarmCachePairMakeSeat(page, member);
    if (!SwarmCachePairSeatUsable(seat)) return false;
    if (contains(page, member)) return false;
    m_pages[page].insert(member);
    return true;
}

} // namespace modelnet
