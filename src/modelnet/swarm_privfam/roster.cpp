// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_privfam/roster.h>

namespace modelnet {

bool SwarmPrivFamRoster::contains(const std::string& family) const
{
    if (family.empty()) return false;
    return m_families.find(family) != m_families.end();
}

bool SwarmPrivFamRoster::private_of(const std::string& family) const
{
    const auto found = m_families.find(family);
    if (found == m_families.end()) return false;
    return found->second.private_flag;
}

std::size_t SwarmPrivFamRoster::size() const
{
    return m_families.size();
}

bool SwarmPrivFamRoster::store(const std::string& family, bool private_flag)
{
    if (contains(family)) return false;
    const SwarmPrivFamRecord record = SwarmPrivFamMakeRecord(family, private_flag);
    if (!SwarmPrivFamRecordUsable(record)) return false;
    m_families.emplace(family, record);
    return true;
}

} // namespace modelnet
