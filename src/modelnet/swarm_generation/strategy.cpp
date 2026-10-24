// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/strategy.h>

#include <utility>

namespace modelnet {

bool SwarmGenerationStrategy::identify(const std::string& weakness, int cycle)
{
    for (const SwarmGenerationStrategyRow& row : m_weaknesses) {
        if (row.weakness == weakness) return false;
    }
    SwarmGenerationStrategyRow row;
    row.weakness = weakness;
    row.cycle = cycle;
    m_weaknesses.push_back(std::move(row));
    return true;
}

const std::string& SwarmGenerationStrategy::latest_weakness() const
{
    if (m_weaknesses.empty()) return m_blank;
    return m_weaknesses.back().weakness;
}

void SwarmGenerationStrategy::grant_eligible()
{
    m_eligible = true;
}

void SwarmGenerationStrategy::allocate(int slots, int exploration_percent, int exploration_slots)
{
    m_allocated = true;
    m_slots = slots;
    m_exploration_percent = exploration_percent;
    m_exploration_slots = exploration_slots;
}

void SwarmGenerationStrategy::add_task(std::string task)
{
    m_tasks.push_back(std::move(task));
}

} // namespace modelnet
