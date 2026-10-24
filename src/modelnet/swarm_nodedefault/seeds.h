// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NODEDEFAULT_SEEDS_H
#define BITCOIN_MODELNET_SWARM_NODEDEFAULT_SEEDS_H

#include <string>
#include <vector>

namespace modelnet {

/**
 * DNS seed list for the default node.
 * dns_seeds() is empty from construction. AddSeed is HELD for every
 * label and does not append. This does not open a socket and does not
 * resolve a name.
 */
class SwarmNodeDefaultSeeds {
public:
    const std::vector<std::string>& dns_seeds() const;
    bool AddSeed(const std::string& seed, std::string& err);

private:
    std::vector<std::string> m_seeds;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NODEDEFAULT_SEEDS_H
