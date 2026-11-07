// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_trajectory.h>

#include <modelnet/swarm_rollout.h>

namespace modelnet {

bool SwarmTrajectoryQueue::BindPolicy(const std::string& policy_version, std::string& err)
{
    if (policy_version.empty()) {
        err = "POLICY";
        return false;
    }
    if (!m_policy.empty() && m_policy != policy_version) {
        err = "STALE_POLICY";
        return false;
    }
    m_policy = policy_version;
    err.clear();
    return true;
}

bool SwarmTrajectoryQueue::Enqueue(const SwarmTrajectoryItem& item, std::string& err)
{
    if (m_policy.empty()) {
        err = "POLICY";
        return false;
    }
    if (item.example_id.empty()) {
        err = "TRAJECTORY";
        return false;
    }
    for (const SwarmTrajectoryRow& row : m_rows) {
        if (row.item.example_id == item.example_id) {
            err = "REPLAY";
            return false;
        }
    }
    if (!SwarmAdmitRollout(item.example_id, item.origin, item.rights_authorized, item.source_evidence, false, err)) {
        return false;
    }
    SwarmTrajectoryRow row;
    row.item = item;
    row.learned = false;
    row.policy_updated = false;
    row.bytes_moved = false;
    m_rows.push_back(std::move(row));
    err.clear();
    return true;
}

bool SwarmTrajectoryQueue::Dequeue(SwarmTrajectoryRow& out, std::string& err)
{
    if (m_rows.empty()) {
        err = "TRAJECTORY";
        return false;
    }
    out = m_rows.front();
    out.learned = false;
    out.policy_updated = false;
    out.bytes_moved = false;
    m_rows.erase(m_rows.begin());
    err.clear();
    return true;
}

std::string SwarmTrajectoryQueue::Policy() const
{
    return m_policy;
}

std::size_t SwarmTrajectoryQueue::Size() const
{
    return m_rows.size();
}

} // namespace modelnet
