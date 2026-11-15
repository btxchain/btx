// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentrun/lease.h>

#include <modelnet/swarm_agentrun/codes.h>
#include <modelnet/swarm_agentrun/task.h>
#include <modelnet/swarm_agentrun/trace.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <utility>

namespace modelnet {

bool SwarmAgentRunLeases::Lease(const SwarmAgentRunTasks& tasks, const std::string& task, const std::string& worker,
                                int64_t epoch, int64_t until_ms, int64_t now_ms, SwarmAgentRunTrace& trace,
                                std::string& err)
{
    if (!tasks.contains(task)) {
        err = kAgentRunTask;
        return false;
    }
    if (worker.empty()) {
        err = kAgentRunWorker;
        return false;
    }
    if (epoch < 0) {
        err = kAgentRunEpoch;
        return false;
    }
    if (now_ms >= until_ms) {
        err = kAgentRunExpired;
        return false;
    }
    if (m_leases.find(task) != m_leases.end()) {
        err = kAgentRunReplay;
        return false;
    }

    SwarmAgentRunLease row;
    row.worker = worker;
    row.epoch = epoch;
    row.until_ms = until_ms;
    row.now_ms = now_ms;
    m_leases.emplace(task, std::move(row));
    trace.Append(kAgentRunEvLease);
    err.clear();
    return true;
}

bool SwarmAgentRunLeases::leased(const std::string& task) const
{
    return m_leases.find(task) != m_leases.end();
}

bool SwarmAgentRunLeases::any() const
{
    return !m_leases.empty();
}

bool SwarmAgentRunLeases::matches(const std::string& task, const std::string& worker, int64_t epoch) const
{
    const auto it = m_leases.find(task);
    if (it == m_leases.end()) {
        return false;
    }
    return it->second.worker == worker && it->second.epoch == epoch;
}

std::string SwarmAgentRunLeases::worker(const std::string& task) const
{
    const auto it = m_leases.find(task);
    if (it == m_leases.end()) {
        return {};
    }
    return it->second.worker;
}

int64_t SwarmAgentRunLeases::epoch(const std::string& task) const
{
    const auto it = m_leases.find(task);
    if (it == m_leases.end()) {
        return 0;
    }
    return it->second.epoch;
}

int64_t SwarmAgentRunLeases::until_ms(const std::string& task) const
{
    const auto it = m_leases.find(task);
    if (it == m_leases.end()) {
        return 0;
    }
    return it->second.until_ms;
}

int64_t SwarmAgentRunLeases::now_ms(const std::string& task) const
{
    const auto it = m_leases.find(task);
    if (it == m_leases.end()) {
        return 0;
    }
    return it->second.now_ms;
}

std::size_t SwarmAgentRunLeases::count() const
{
    return m_leases.size();
}

} // namespace modelnet
