// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_budget.h>

namespace modelnet {

bool SwarmResearchBudget::Open(const std::string& experiment, int64_t slots, std::string& err)
{
    if (experiment.empty()) {
        err = "EXPERIMENT";
        return false;
    }
    if (slots < 1) {
        err = "BUDGET";
        return false;
    }
    if (m_remaining.find(experiment) != m_remaining.end()) {
        err = "REPLAY";
        return false;
    }
    m_remaining.emplace(experiment, slots);
    err.clear();
    return true;
}

bool SwarmResearchBudget::Spend(const std::string& experiment, int64_t slots, std::string& err)
{
    const auto it = m_remaining.find(experiment);
    if (it == m_remaining.end()) {
        err = "EXPERIMENT";
        return false;
    }
    if (slots < 1) {
        err = "BUDGET";
        return false;
    }
    if (slots > it->second) {
        err = "EXHAUSTED";
        return false;
    }
    it->second -= slots;
    err.clear();
    return true;
}

int64_t SwarmResearchBudget::Remaining(const std::string& experiment) const
{
    const auto it = m_remaining.find(experiment);
    if (it == m_remaining.end()) return -1;
    return it->second;
}

} // namespace modelnet
