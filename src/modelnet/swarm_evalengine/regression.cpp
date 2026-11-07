// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalengine/regression.h>

namespace modelnet {

void SwarmEvaluationRegressionBook::add(const SwarmEvaluationRegression& report)
{
    m_rows.push_back(report);
}

bool SwarmEvaluationRegressionBook::contains(const std::string& candidate) const
{
    return count_for(candidate) != 0;
}

std::size_t SwarmEvaluationRegressionBook::count_for(const std::string& candidate) const
{
    std::size_t count = 0;
    for (const SwarmEvaluationRegression& row : m_rows) {
        if (row.candidate == candidate) {
            ++count;
        }
    }
    return count;
}

std::size_t SwarmEvaluationRegressionBook::size() const
{
    return m_rows.size();
}

} // namespace modelnet
