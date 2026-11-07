// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentrun/branch.h>

#include <modelnet/swarm_agentrun/codes.h>
#include <modelnet/swarm_agentrun/result.h>
#include <modelnet/swarm_agentrun/task.h>
#include <modelnet/swarm_agentrun/trace.h>

#include <cstddef>
#include <map>
#include <string>

namespace modelnet {

bool SwarmAgentRunBranches::Speculate(const SwarmAgentRunTasks& tasks, const std::string& branch,
                                      const std::string& task, SwarmAgentRunTrace& trace, std::string& err)
{
    if (branch.empty()) {
        err = kAgentRunBranch;
        return false;
    }
    if (!tasks.contains(task)) {
        err = kAgentRunTask;
        return false;
    }
    if (m_branches.find(branch) != m_branches.end()) {
        err = kAgentRunReplay;
        return false;
    }
    m_branches.emplace(branch, task);
    trace.Append(kAgentRunEvSpeculate);
    err.clear();
    return true;
}

bool SwarmAgentRunBranches::Reconcile(const SwarmAgentRunResults& results, const std::string& branch, std::string& err)
{
    const auto it = m_branches.find(branch);
    if (it == m_branches.end()) {
        err = kAgentRunBranch;
        return false;
    }
    if (results.has_receipt(it->second)) {
        m_branches.erase(it);
        err = kAgentRunDropped;
        return false;
    }
    err.clear();
    return true;
}

bool SwarmAgentRunBranches::contains(const std::string& branch) const
{
    return m_branches.find(branch) != m_branches.end();
}

std::string SwarmAgentRunBranches::task_of(const std::string& branch) const
{
    const auto it = m_branches.find(branch);
    if (it == m_branches.end()) {
        return {};
    }
    return it->second;
}

std::size_t SwarmAgentRunBranches::count() const
{
    return m_branches.size();
}

} // namespace modelnet
