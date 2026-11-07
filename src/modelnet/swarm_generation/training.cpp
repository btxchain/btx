// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/training.h>

#include <utility>

namespace modelnet {

void SwarmGenerationTraining::add(int cycle, std::string outcome)
{
    SwarmGenerationTrainAttempt row;
    row.cycle = cycle;
    row.outcome = std::move(outcome);
    m_rows.push_back(std::move(row));
}

} // namespace modelnet
