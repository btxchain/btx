// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_STRATEGY_H
#define BITCOIN_MODELNET_SWARM_GENERATION_STRATEGY_H

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

struct SwarmGenerationStrategyRow {
    std::string weakness;
    int cycle{0};
};

/**
 * Research strategies opened by Identify.
 * Eligibility starts false. A download is not stored as a training grant.
 * Allocation stores an integer exploration share. Niches are not ranked.
 */
class SwarmGenerationStrategy {
public:
    bool identify(const std::string& weakness, int cycle);
    bool has_weakness() const { return !m_weaknesses.empty(); }
    std::size_t weakness_count() const { return m_weaknesses.size(); }
    const std::string& latest_weakness() const;

    void grant_eligible();
    bool eligible() const { return m_eligible; }

    void allocate(int slots, int exploration_percent, int exploration_slots);
    int exploration_slots() const { return m_exploration_slots; }
    bool allocated() const { return m_allocated; }

    void add_task(std::string task);
    std::size_t task_count() const { return m_tasks.size(); }
    const std::vector<std::string>& tasks() const { return m_tasks; }
    const std::vector<SwarmGenerationStrategyRow>& weaknesses() const { return m_weaknesses; }

private:
    std::vector<SwarmGenerationStrategyRow> m_weaknesses;
    bool m_eligible{false};
    bool m_allocated{false};
    int m_slots{0};
    int m_exploration_percent{0};
    int m_exploration_slots{0};
    std::vector<std::string> m_tasks;
    std::string m_blank;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_STRATEGY_H
