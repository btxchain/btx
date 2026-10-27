// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTRUN_RESULT_H
#define BITCOIN_MODELNET_SWARM_AGENTRUN_RESULT_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

class SwarmAgentRunLeases;
class SwarmAgentRunTasks;
class SwarmAgentRunTrace;

/** One assignment. A task has at most one. */
struct SwarmAgentRunAssignment {
    std::string worker;
    int64_t epoch{0};
};

/**
 * Assignments and receipts.
 * Assign requires the stored lease to match worker and epoch. Otherwise
 * the call is FENCE and does not assign. A second Assign of that same
 * task, worker, and epoch is REPLAY and does not add a second assignment.
 * An empty receipt is RECEIPT. An unknown or unassigned task is
 * NOT_ASSIGNED. The first receipt is stored. The same receipt again is
 * REPLAY. A different receipt is CONFLICT and the first receipt stays.
 * Cancel does not erase a receipt. This book does not consult the
 * cancelled flag, so a later first receipt can still be stored.
 */
class SwarmAgentRunResults {
public:
    bool Assign(const SwarmAgentRunLeases& leases, const std::string& task, const std::string& worker, int64_t epoch,
                SwarmAgentRunTrace& trace, std::string& err);
    bool Commit(const SwarmAgentRunTasks& tasks, const std::string& task, const std::string& receipt,
                SwarmAgentRunTrace& trace, std::string& err);

    bool assigned(const std::string& task) const;
    std::string assigned_worker(const std::string& task) const;
    int64_t assigned_epoch(const std::string& task) const;
    bool has_receipt(const std::string& task) const;
    std::string receipt(const std::string& task) const;
    std::size_t assignment_count() const;
    std::size_t receipt_count() const;

private:
    std::map<std::string, SwarmAgentRunAssignment> m_assigned;
    std::map<std::string, std::string> m_receipts;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTRUN_RESULT_H
