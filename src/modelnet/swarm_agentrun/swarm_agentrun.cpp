// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentrun/swarm_agentrun.h>

#include <modelnet/swarm_agentrun/leader.h>
#include <modelnet/swarm_agentrun/sandbox.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

bool SwarmAgentRun::AddTask(const std::string& id, const std::string& parent, const std::string& capability,
                            std::string& err)
{
    return m_tasks.Add(id, parent, capability, m_trace, err);
}

bool SwarmAgentRun::Lease(const std::string& task, const std::string& worker, int64_t epoch, int64_t until_ms,
                          int64_t now_ms, std::string& err)
{
    return m_leases.Lease(m_tasks, task, worker, epoch, until_ms, now_ms, m_trace, err);
}

bool SwarmAgentRun::Assign(const std::string& task, const std::string& worker, int64_t epoch, std::string& err)
{
    return m_results.Assign(m_leases, task, worker, epoch, m_trace, err);
}

bool SwarmAgentRun::CommitResult(const std::string& task, const std::string& receipt, std::string& err)
{
    return m_results.Commit(m_tasks, task, receipt, m_trace, err);
}

bool SwarmAgentRun::LeaderGone(std::string& err) const
{
    return SwarmAgentRunLeaderGone(m_leases, err);
}

bool SwarmAgentRun::Speculate(const std::string& branch, const std::string& task, std::string& err)
{
    return m_branches.Speculate(m_tasks, branch, task, m_trace, err);
}

bool SwarmAgentRun::Reconcile(const std::string& branch, std::string& err)
{
    return m_branches.Reconcile(m_results, branch, err);
}

bool SwarmAgentRun::ReuseTool(const std::string& digest, bool is_private, std::string& err)
{
    return m_tools.Reuse(digest, is_private, m_trace, err);
}

bool SwarmAgentRun::Cancel(const std::string& task, std::string& err)
{
    return m_tasks.Cancel(task, m_trace, err);
}

bool SwarmAgentRun::Run(std::string& err)
{
    return SwarmAgentRunSandboxRefuse(m_trace, err);
}

std::vector<std::string> SwarmAgentRun::Trace() const
{
    return m_trace.events();
}

std::size_t SwarmAgentRun::task_count() const
{
    return m_tasks.count();
}

bool SwarmAgentRun::has_task(const std::string& id) const
{
    return m_tasks.contains(id);
}

std::string SwarmAgentRun::parent_of(const std::string& id) const
{
    return m_tasks.parent_of(id);
}

std::string SwarmAgentRun::capability_of(const std::string& id) const
{
    return m_tasks.capability_of(id);
}

std::vector<std::string> SwarmAgentRun::children_of(const std::string& id) const
{
    return m_tasks.children_of(id);
}

bool SwarmAgentRun::leased(const std::string& task) const
{
    return m_leases.leased(task);
}

std::string SwarmAgentRun::lease_worker(const std::string& task) const
{
    return m_leases.worker(task);
}

int64_t SwarmAgentRun::lease_epoch(const std::string& task) const
{
    return m_leases.epoch(task);
}

int64_t SwarmAgentRun::lease_until_ms(const std::string& task) const
{
    return m_leases.until_ms(task);
}

int64_t SwarmAgentRun::lease_now_ms(const std::string& task) const
{
    return m_leases.now_ms(task);
}

bool SwarmAgentRun::assigned(const std::string& task) const
{
    return m_results.assigned(task);
}

std::string SwarmAgentRun::assigned_worker(const std::string& task) const
{
    return m_results.assigned_worker(task);
}

int64_t SwarmAgentRun::assigned_epoch(const std::string& task) const
{
    return m_results.assigned_epoch(task);
}

std::string SwarmAgentRun::receipt(const std::string& task) const
{
    return m_results.receipt(task);
}

std::size_t SwarmAgentRun::branch_count() const
{
    return m_branches.count();
}

bool SwarmAgentRun::has_branch(const std::string& branch) const
{
    return m_branches.contains(branch);
}

std::string SwarmAgentRun::branch_task(const std::string& branch) const
{
    return m_branches.task_of(branch);
}

std::size_t SwarmAgentRun::tool_count() const
{
    return m_tools.count();
}

bool SwarmAgentRun::tool(const std::string& digest) const
{
    return m_tools.contains(digest);
}

bool SwarmAgentRun::cancelled(const std::string& task) const
{
    return m_tasks.cancelled(task);
}

bool SwarmAgentRun::launched() const
{
    return m_quiet.launched();
}

bool SwarmAgentRun::gpu() const
{
    return m_quiet.gpu();
}

int64_t SwarmAgentRun::bytes_moved() const
{
    return m_quiet.bytes_moved();
}

int64_t SwarmAgentRun::atoms_moved() const
{
    return m_quiet.atoms_moved();
}

std::string SwarmAgentRun::automatic_spend() const
{
    return m_quiet.automatic_spend();
}

bool SwarmAgentRun::broadcast() const
{
    return m_quiet.broadcast();
}

} // namespace modelnet
