// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/specialist.h>

#include <utility>

namespace modelnet {

void SwarmGenerationSpecialists::add(std::string name, std::string candidate_id)
{
    SwarmGenerationSpecialistRow row;
    row.name = std::move(name);
    row.candidate_id = std::move(candidate_id);
    m_rows.push_back(std::move(row));
}

} // namespace modelnet
