// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rewardloop.h>

#include <algorithm>

namespace modelnet {

bool SwarmRewardLoop::Store(const std::string& id, const std::string& kind, int64_t outcome_ppm, std::string& err)
{
    if (id.empty()) {
        err = "ITEM";
        return false;
    }
    if (kind != "public_trajectory" && kind != "synthetic_trajectory") {
        err = "PRIVATE_DATA";
        return false;
    }
    if (outcome_ppm < 0 || outcome_ppm > 1000000) {
        err = "RANGE";
        return false;
    }
    if (m_rows.find(id) != m_rows.end()) {
        err = "REPLAY";
        return false;
    }
    Row row;
    row.kind = kind;
    row.outcome_ppm = outcome_ppm;
    row.reward = outcome_ppm >= 500000 ? 1 : 0;
    m_rows.emplace(id, row);
    err.clear();
    return true;
}

int SwarmRewardLoop::reward(const std::string& id) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end()) return -1;
    return it->second.reward;
}

bool SwarmRewardLoop::Enqueue(const std::string& id, std::string& err)
{
    if (m_rows.find(id) == m_rows.end()) {
        err = "ITEM";
        return false;
    }
    if (std::find(m_queue.begin(), m_queue.end(), id) != m_queue.end()) {
        err = "REPLAY";
        return false;
    }
    m_queue.push_back(id);
    err.clear();
    return true;
}

const std::vector<std::string>& SwarmRewardLoop::Queue() const
{
    return m_queue;
}

} // namespace modelnet
