// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAMILYADMIT_ROSTER_H
#define BITCOIN_MODELNET_SWARM_FAMILYADMIT_ROSTER_H

#include <modelnet/swarm_familyadmit/record.h>

#include <cstddef>
#include <map>
#include <string>

namespace modelnet {

/**
 * Peers stored by a successful Admit, keyed by peer id.
 * store refuses an empty id, an empty family, and a peer already present.
 * A refused store leaves the first family in place. There is no erase
 * and no method that marks a peer connected.
 */
class SwarmFamilyAdmitRoster {
public:
    bool contains(const std::string& peer) const;
    std::string family_of(const std::string& peer) const;
    std::size_t size() const;

    /**
     * Store peer with family.
     * Refuses an unusable record and a duplicate peer. On refusal the
     * roster is unchanged.
     */
    bool store(const std::string& peer, const std::string& family);

private:
    std::map<std::string, SwarmFamilyAdmitRecord> m_peers;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAMILYADMIT_ROSTER_H
