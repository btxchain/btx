// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_READFENCE_ROSTER_H
#define BITCOIN_MODELNET_SWARM_READFENCE_ROSTER_H

#include <cstddef>
#include <set>
#include <string>

namespace modelnet {

/**
 * Members who cannot read a placed page.
 * Revoke stores a non-empty member once.
 * An empty member is refused. A member already revoked is refused.
 * There is no way to clear a revoke.
 */
class SwarmReadRoster {
public:
    bool revoked(const std::string& member) const;
    std::size_t size() const;

    bool Revoke(const std::string& member);

private:
    std::set<std::string> m_members;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_READFENCE_ROSTER_H
