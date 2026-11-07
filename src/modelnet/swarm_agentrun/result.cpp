// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentrun/result.h>

#include <modelnet/swarm_agentrun/codes.h>
#include <modelnet/swarm_agentrun/lease.h>
#include <modelnet/swarm_agentrun/task.h>
#include <modelnet/swarm_agentrun/trace.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <utility>

namespace modelnet {

bool SwarmAgentRunResults::Assign(const SwarmAgentRunLeases& leases, const std::string& task, const std::string& worker,
                                  int64_t epoch, SwarmAgentRunTrace& trace, std::string& err)
{
    if (!leases.matches(task, worker, epoch)) {
        err = kAgentRunFence;
        return false;
    }
    const auto it = m_assigned.find(task);
    if (it != m_assigned.end()) {
        err = kAgentRunReplay;
        return false;
    }

    SwarmAgentRunAssignment row;
    row.worker = worker;
    row.epoch = epoch;
    m_assigned.emplace(task, std::move(row));
    trace.Append(kAgentRunEvAssign);
    err.clear();
    return true;
}

bool SwarmAgentRunResults::Commit(const SwarmAgentRunTasks& tasks, const std::string& task, const std::string& receipt,
                                  SwarmAgentRunTrace& trace, std::string& err)
{
    if (receipt.empty()) {
        err = kAgentRunReceipt;
        return false;
    }
    if (!tasks.contains(task) || !assigned(task)) {
        err = kAgentRunNotAssigned;
        return false;
    }
    const auto it = m_receipts.find(task);
    if (it == m_receipts.end()) {
        m_receipts.emplace(task, receipt);
        trace.Append(kAgentRunEvCommit);
        err.clear();
        return true;
    }
    if (it->second == receipt) {
        err = kAgentRunReplay;
        return false;
    }
    err = kAgentRunConflict;
    return false;
}

bool SwarmAgentRunResults::assigned(const std::string& task) const
{
    return m_assigned.find(task) != m_assigned.end();
}

std::string SwarmAgentRunResults::assigned_worker(const std::string& task) const
{
    const auto it = m_assigned.find(task);
    if (it == m_assigned.end()) {
        return {};
    }
    return it->second.worker;
}

int64_t SwarmAgentRunResults::assigned_epoch(const std::string& task) const
{
    const auto it = m_assigned.find(task);
    if (it == m_assigned.end()) {
        return 0;
    }
    return it->second.epoch;
}

bool SwarmAgentRunResults::has_receipt(const std::string& task) const
{
    return m_receipts.find(task) != m_receipts.end();
}

std::string SwarmAgentRunResults::receipt(const std::string& task) const
{
    const auto it = m_receipts.find(task);
    if (it == m_receipts.end()) {
        return {};
    }
    return it->second;
}

std::size_t SwarmAgentRunResults::assignment_count() const
{
    return m_assigned.size();
}

std::size_t SwarmAgentRunResults::receipt_count() const
{
    return m_receipts.size();
}

} // namespace modelnet
