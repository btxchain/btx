// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_leaderepoch.h>

namespace modelnet {

bool SwarmLeaderEpoch::Claim(const std::string& leader, int64_t epoch, std::string& err)
{
    if (leader.empty()) {
        err = "LEADER";
        return false;
    }
    if (epoch != m_epoch) {
        err = "STALE_EPOCH";
        return false;
    }
    m_leader = leader;
    err.clear();
    return true;
}

void SwarmLeaderEpoch::Bump()
{
    ++m_epoch;
    m_leader.clear();
}

bool SwarmLeaderEpoch::Assign(const std::string& leader, int64_t epoch, const std::string& task, std::string& err)
{
    if (leader != m_leader || epoch != m_epoch) {
        err = "STALE_EPOCH";
        return false;
    }
    if (task.empty()) {
        err = "TASK";
        return false;
    }
    if (m_assignments.find(task) != m_assignments.end()) {
        err = "REPLAY";
        return false;
    }
    Assignment row;
    row.leader = leader;
    row.epoch = epoch;
    m_assignments.emplace(task, row);
    err.clear();
    return true;
}

std::string SwarmLeaderEpoch::Leader() const
{
    return m_leader;
}

int64_t SwarmLeaderEpoch::epoch() const
{
    return m_epoch;
}

} // namespace modelnet
