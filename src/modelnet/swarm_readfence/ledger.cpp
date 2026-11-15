// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_readfence/ledger.h>

namespace modelnet {

bool SwarmReadLedger::recorded(const std::string& member, const std::string& page) const
{
    return m_reads.find(std::make_pair(member, page)) != m_reads.end();
}

std::size_t SwarmReadLedger::size() const
{
    return m_reads.size();
}

bool SwarmReadLedger::Record(const std::string& member, const std::string& page)
{
    if (member.empty() || page.empty()) return false;
    m_reads.insert(std::make_pair(member, page));
    return true;
}

} // namespace modelnet
