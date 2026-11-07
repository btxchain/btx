// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cachepair/swarm_cachepair.h>

#include <modelnet/swarm_cachepair/place.h>
#include <modelnet/swarm_cachepair/share.h>

namespace modelnet {

bool SwarmCachePair::Place(const std::string& page, const std::string& member, std::string& err)
{
    return SwarmCachePairPlace(m_roster, page, member, err);
}

bool SwarmCachePair::Share(const std::string& page, std::string& err)
{
    return SwarmCachePairShare(m_roster, m_book, page, err);
}

bool SwarmCachePair::placed(const std::string& page, const std::string& member) const
{
    return m_roster.contains(page, member);
}

std::size_t SwarmCachePair::member_count(const std::string& page) const
{
    return m_roster.members(page);
}

std::size_t SwarmCachePair::page_count() const
{
    return m_roster.pages();
}

std::vector<std::string> SwarmCachePair::members(const std::string& page) const
{
    return m_roster.list(page);
}

bool SwarmCachePair::shared(const std::string& page) const
{
    return m_book.contains(page);
}

std::size_t SwarmCachePair::share_count() const
{
    return m_book.size();
}

std::vector<std::string> SwarmCachePair::shared_members(const std::string& page) const
{
    return m_book.members_of(page);
}

int64_t SwarmCachePair::bytes_moved() const
{
    return m_quiet.bytes_moved();
}

bool SwarmCachePair::cuda_buffer() const
{
    return m_quiet.cuda_buffer();
}

bool SwarmCachePair::launched() const
{
    return m_quiet.launched();
}

} // namespace modelnet
