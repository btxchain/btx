// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTRUN_BRANCH_H
#define BITCOIN_MODELNET_SWARM_AGENTRUN_BRANCH_H

#include <cstddef>
#include <map>
#include <string>

namespace modelnet {

class SwarmAgentRunResults;
class SwarmAgentRunTasks;
class SwarmAgentRunTrace;

/**
 * Speculative branches keyed by branch id. The value is the task id.
 * A branch does not write a receipt. Reconcile drops the branch when
 * that task already has a receipt and leaves the receipt in place.
 * A branch whose task has no receipt stays stored.
 */
class SwarmAgentRunBranches {
public:
    bool Speculate(const SwarmAgentRunTasks& tasks, const std::string& branch, const std::string& task,
                   SwarmAgentRunTrace& trace, std::string& err);
    bool Reconcile(const SwarmAgentRunResults& results, const std::string& branch, std::string& err);

    bool contains(const std::string& branch) const;
    std::string task_of(const std::string& branch) const;
    std::size_t count() const;

private:
    std::map<std::string, std::string> m_branches;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTRUN_BRANCH_H
