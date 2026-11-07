// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ISLANDGATE_ROSTER_H
#define BITCOIN_MODELNET_SWARM_ISLANDGATE_ROSTER_H

#include <modelnet/swarm_islandgate/record.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Islands stored by a successful Admit, keyed by island id.
 * store refuses an empty id and an island already present.
 * A refused store leaves the first epoch in place. There is no erase.
 */
class SwarmIslandGateRoster {
public:
    bool contains(const std::string& island) const;
    int64_t epoch_of(const std::string& island) const;
    std::size_t size() const;

    /**
     * Store island with epoch.
     * Refuses an unusable record and a duplicate island. On refusal the
     * roster is unchanged.
     */
    bool store(const std::string& island, int64_t epoch);

private:
    std::map<std::string, SwarmIslandGateRecord> m_islands;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ISLANDGATE_ROSTER_H
