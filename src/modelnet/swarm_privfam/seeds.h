// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PRIVFAM_SEEDS_H
#define BITCOIN_MODELNET_SWARM_PRIVFAM_SEEDS_H

#include <string>
#include <vector>

namespace modelnet {

/**
 * DNS seed list for this plane.
 * The list starts empty. Add refuses every host, sets err to HELD, and
 * does not append. There is no method that connects through a seed.
 */
class SwarmPrivFamSeeds {
public:
    bool Add(const std::string& host, std::string& err);
    const std::vector<std::string>& list() const;

private:
    std::vector<std::string> m_seeds;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PRIVFAM_SEEDS_H
