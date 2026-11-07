// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_familyadmit/roster.h>

namespace modelnet {

bool SwarmFamilyAdmitRoster::contains(const std::string& peer) const
{
    if (peer.empty()) return false;
    return m_peers.find(peer) != m_peers.end();
}

std::string SwarmFamilyAdmitRoster::family_of(const std::string& peer) const
{
    const auto found = m_peers.find(peer);
    if (found == m_peers.end()) return {};
    return found->second.family;
}

std::size_t SwarmFamilyAdmitRoster::size() const
{
    return m_peers.size();
}

bool SwarmFamilyAdmitRoster::store(const std::string& peer, const std::string& family)
{
    if (contains(peer)) return false;
    const SwarmFamilyAdmitRecord record = SwarmFamilyAdmitMakeRecord(peer, family);
    if (!SwarmFamilyAdmitRecordUsable(record)) return false;
    m_peers.emplace(peer, record);
    return true;
}

} // namespace modelnet
