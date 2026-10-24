// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTRUN_H
#define BITCOIN_MODELNET_SWARM_AGENTRUN_H

#include <modelnet/swarm_agentrun/branch.h>
#include <modelnet/swarm_agentrun/lease.h>
#include <modelnet/swarm_agentrun/quiet.h>
#include <modelnet/swarm_agentrun/result.h>
#include <modelnet/swarm_agentrun/task.h>
#include <modelnet/swarm_agentrun/tool.h>
#include <modelnet/swarm_agentrun/trace.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * In-process agent run engine.
 * Tasks form a forest. Leases fence assignment by worker and epoch.
 * The first receipt stays. Speculative branches do not write receipts.
 * Public tool digests are stored once. The trace lists successful stores
 * and Run refusals.
 *
 * AddTask stores id, parent, and capability. Empty id is TASK. A non-empty
 * unknown parent is DEPENDENCY and stores nothing, even for an id that
 * already exists. An empty parent is a root. A duplicate id whose parent
 * is empty or already a task is REPLAY and keeps the first task.
 *
 * Lease stores one lease per task. Unknown task is TASK. Empty worker is
 * WORKER. Epoch below 0 is EPOCH. now_ms >= until_ms, including equality,
 * is EXPIRED and stores nothing. A second valid lease is REPLAY.
 *
 * Assign is FENCE unless the stored lease matches worker and epoch.
 * A second Assign of that triple is REPLAY.
 *
 * CommitResult stores the first receipt. Empty receipt is RECEIPT.
 * Unknown or unassigned task is NOT_ASSIGNED. The same receipt is REPLAY.
 * A different receipt is CONFLICT and the first stays.
 *
 * LeaderGone returns false. Any lease is DURABLE. No lease is LOST.
 * It deletes nothing and writes no trace row.
 *
 * Speculate stores a branch and does not change a receipt. Empty branch
 * is BRANCH. Unknown task is TASK. A duplicate branch id is REPLAY.
 * Reconcile of an unknown branch is BRANCH. A branch whose task already
 * has a receipt is dropped and returns false with DROPPED. The receipt
 * stays. A branch whose task has no receipt stays and returns true.
 *
 * ReuseTool stores a public digest once. Empty digest is TOOL. Private
 * data is PRIVATE_DATA and stores nothing. A second public store is
 * REPLAY. tool() is true for a stored public digest.
 *
 * Cancel of an unknown task is TASK. Otherwise the task is cancelled.
 * A stored receipt stays. A second cancel is REPLAY.
 *
 * Run always returns false with SANDBOX_ABSENT and appends that name.
 * launched() stays false. gpu() stays false. bytes_moved() stays 0.
 * atoms_moved() stays 0. automatic_spend() stays "0". broadcast() stays
 * false. No method sets launched() true. This plane does not start a
 * process, open a socket, broadcast, or spend.
 */
class SwarmAgentRun {
public:
    bool AddTask(const std::string& id, const std::string& parent, const std::string& capability, std::string& err);
    bool Lease(const std::string& task, const std::string& worker, int64_t epoch, int64_t until_ms, int64_t now_ms,
               std::string& err);
    bool Assign(const std::string& task, const std::string& worker, int64_t epoch, std::string& err);
    bool CommitResult(const std::string& task, const std::string& receipt, std::string& err);
    bool LeaderGone(std::string& err) const;
    bool Speculate(const std::string& branch, const std::string& task, std::string& err);
    bool Reconcile(const std::string& branch, std::string& err);
    bool ReuseTool(const std::string& digest, bool is_private, std::string& err);
    bool Cancel(const std::string& task, std::string& err);
    bool Run(std::string& err);

    std::vector<std::string> Trace() const;

    std::size_t task_count() const;
    bool has_task(const std::string& id) const;
    std::string parent_of(const std::string& id) const;
    std::string capability_of(const std::string& id) const;
    std::vector<std::string> children_of(const std::string& id) const;
    bool leased(const std::string& task) const;
    std::string lease_worker(const std::string& task) const;
    int64_t lease_epoch(const std::string& task) const;
    int64_t lease_until_ms(const std::string& task) const;
    int64_t lease_now_ms(const std::string& task) const;
    bool assigned(const std::string& task) const;
    std::string assigned_worker(const std::string& task) const;
    int64_t assigned_epoch(const std::string& task) const;
    std::string receipt(const std::string& task) const;
    std::size_t branch_count() const;
    bool has_branch(const std::string& branch) const;
    std::string branch_task(const std::string& branch) const;
    std::size_t tool_count() const;
    bool tool(const std::string& digest) const;
    bool cancelled(const std::string& task) const;
    bool launched() const;
    bool gpu() const;
    int64_t bytes_moved() const;
    int64_t atoms_moved() const;
    std::string automatic_spend() const;
    bool broadcast() const;

private:
    SwarmAgentRunTasks m_tasks;
    SwarmAgentRunLeases m_leases;
    SwarmAgentRunResults m_results;
    SwarmAgentRunBranches m_branches;
    SwarmAgentRunTools m_tools;
    SwarmAgentRunTrace m_trace;
    SwarmAgentRunQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTRUN_H
