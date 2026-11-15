// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/rollback.h>

#include <utility>

namespace modelnet {

void SwarmGenerationRollbacks::push(std::string channel, std::string previous_active)
{
    SwarmGenerationRollbackRow row;
    row.channel = std::move(channel);
    row.previous_active = std::move(previous_active);
    m_rows.push_back(std::move(row));
}

} // namespace modelnet
