// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/negative.h>

#include <utility>

namespace modelnet {

void SwarmGenerationNegatives::add(std::string result)
{
    m_rows.push_back(std::move(result));
}

bool SwarmGenerationNegatives::contains(const std::string& result) const
{
    for (const std::string& row : m_rows) {
        if (row == result) return true;
    }
    return false;
}

} // namespace modelnet
