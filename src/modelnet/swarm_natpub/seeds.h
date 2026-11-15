// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NATPUB_SEEDS_H
#define BITCOIN_MODELNET_SWARM_NATPUB_SEEDS_H

#include <string>
#include <vector>

namespace modelnet {

/**
 * DNS seed list for this plane.
 * The list starts empty. There is no method that appends an endpoint.
 * dns_seeds() stays empty.
 */
class SwarmNatPubSeeds {
public:
    const std::vector<std::string>& list() const;

private:
    std::vector<std::string> m_seeds;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NATPUB_SEEDS_H
