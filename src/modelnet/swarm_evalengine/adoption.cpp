// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalengine/adoption.h>

namespace modelnet {

void SwarmEvaluationAdoptionBook::push(const std::string& channel, const std::string& previous_active, const std::string& adopted)
{
    SwarmEvaluationAdoption row;
    row.channel = channel;
    row.previous_active = previous_active;
    row.adopted = adopted;
    m_rows.push_back(row);
}

std::size_t SwarmEvaluationAdoptionBook::count(const std::string& channel) const
{
    std::size_t n = 0;
    for (const SwarmEvaluationAdoption& row : m_rows) {
        if (row.channel == channel) {
            ++n;
        }
    }
    return n;
}

} // namespace modelnet
