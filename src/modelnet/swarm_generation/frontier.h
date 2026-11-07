// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_FRONTIER_H
#define BITCOIN_MODELNET_SWARM_GENERATION_FRONTIER_H

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

struct SwarmGenerationProposal {
    std::string experiment;
    std::string weakness;
};

/**
 * Proposals sitting on the frontier. Niches are not ranked here.
 */
class SwarmGenerationFrontier {
public:
    std::size_t count() const { return m_rows.size(); }
    void add(std::string experiment, std::string weakness);
    const std::vector<SwarmGenerationProposal>& rows() const { return m_rows; }

private:
    std::vector<SwarmGenerationProposal> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_FRONTIER_H
