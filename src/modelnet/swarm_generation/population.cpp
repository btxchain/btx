// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/population.h>

#include <utility>

namespace modelnet {

const std::string& SwarmGenerationPopulation::last_id() const
{
    if (m_last_id.empty()) return m_blank;
    return m_last_id;
}

const SwarmGenerationCandidate* SwarmGenerationPopulation::find(const std::string& id) const
{
    for (const SwarmGenerationCandidate& row : m_rows) {
        if (row.id == id) return &row;
    }
    return nullptr;
}

SwarmGenerationCandidate* SwarmGenerationPopulation::find_mut(const std::string& id)
{
    for (SwarmGenerationCandidate& row : m_rows) {
        if (row.id == id) return &row;
    }
    return nullptr;
}

bool SwarmGenerationPopulation::store(SwarmGenerationCandidate candidate)
{
    m_last_id = candidate.id;
    if (find(candidate.id) != nullptr) return true;
    m_rows.push_back(std::move(candidate));
    return true;
}

bool SwarmGenerationPopulation::mark_verified(const std::string& id, const std::string& parent)
{
    SwarmGenerationCandidate* row = find_mut(id);
    if (row == nullptr) return false;
    if (row->parent != parent) return false;
    row->verified = true;
    return true;
}

bool SwarmGenerationPopulation::verified(const std::string& id) const
{
    const SwarmGenerationCandidate* row = find(id);
    return row != nullptr && row->verified;
}

} // namespace modelnet
