// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/adoption.h>

#include <utility>

namespace modelnet {

void SwarmGenerationAdoptions::add(std::string channel, std::string candidate_id)
{
    SwarmGenerationAdoptionRow row;
    row.channel = std::move(channel);
    row.candidate_id = std::move(candidate_id);
    m_rows.push_back(std::move(row));
}

} // namespace modelnet
