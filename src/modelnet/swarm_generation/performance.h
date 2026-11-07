// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_PERFORMANCE_H
#define BITCOIN_MODELNET_SWARM_GENERATION_PERFORMANCE_H

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

struct SwarmGenerationComparison {
    std::string left;
    std::string right;
};

/**
 * Compatible comparisons. The weights of the two sides are not averaged.
 */
class SwarmGenerationPerformance {
public:
    std::size_t count() const { return m_rows.size(); }
    void add(std::string left, std::string right);
    const std::vector<SwarmGenerationComparison>& rows() const { return m_rows; }

private:
    std::vector<SwarmGenerationComparison> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_PERFORMANCE_H
