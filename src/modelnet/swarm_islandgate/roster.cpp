// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_islandgate/roster.h>

namespace modelnet {

bool SwarmIslandGateRoster::contains(const std::string& island) const
{
    if (island.empty()) return false;
    return m_islands.find(island) != m_islands.end();
}

int64_t SwarmIslandGateRoster::epoch_of(const std::string& island) const
{
    const auto found = m_islands.find(island);
    if (found == m_islands.end()) return 0;
    return found->second.epoch;
}

std::size_t SwarmIslandGateRoster::size() const
{
    return m_islands.size();
}

bool SwarmIslandGateRoster::store(const std::string& island, int64_t epoch)
{
    if (contains(island)) return false;
    const SwarmIslandGateRecord record = SwarmIslandGateMakeRecord(island, epoch);
    if (!SwarmIslandGateRecordUsable(record)) return false;
    m_islands.emplace(island, record);
    return true;
}

} // namespace modelnet
