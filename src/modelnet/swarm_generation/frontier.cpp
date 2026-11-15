// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/frontier.h>

#include <utility>

namespace modelnet {

void SwarmGenerationFrontier::add(std::string experiment, std::string weakness)
{
    SwarmGenerationProposal row;
    row.experiment = std::move(experiment);
    row.weakness = std::move(weakness);
    m_rows.push_back(std::move(row));
}

} // namespace modelnet
