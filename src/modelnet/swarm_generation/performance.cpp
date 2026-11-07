// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/performance.h>

#include <utility>

namespace modelnet {

void SwarmGenerationPerformance::add(std::string left, std::string right)
{
    SwarmGenerationComparison row;
    row.left = std::move(left);
    row.right = std::move(right);
    m_rows.push_back(std::move(row));
}

} // namespace modelnet
