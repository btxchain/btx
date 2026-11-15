// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/challenger.h>

#include <utility>

namespace modelnet {

void SwarmGenerationChallengers::add(std::string candidate_id, std::string parent)
{
    SwarmGenerationChallengerRow row;
    row.candidate_id = std::move(candidate_id);
    row.parent = std::move(parent);
    m_rows.push_back(std::move(row));
}

} // namespace modelnet
