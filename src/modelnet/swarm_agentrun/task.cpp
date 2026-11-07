// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentrun/task.h>

#include <modelnet/swarm_agentrun/codes.h>
#include <modelnet/swarm_agentrun/trace.h>

#include <cstddef>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {

bool SwarmAgentRunTasks::Add(const std::string& id, const std::string& parent, const std::string& capability,
                             SwarmAgentRunTrace& trace, std::string& err)
{
    if (id.empty()) {
        err = kAgentRunTask;
        return false;
    }
    if (!parent.empty() && m_tasks.find(parent) == m_tasks.end()) {
        err = kAgentRunDependency;
        return false;
    }
    if (m_tasks.find(id) != m_tasks.end()) {
        err = kAgentRunReplay;
        return false;
    }

    SwarmAgentRunTask row;
    row.parent = parent;
    row.capability = capability;
    row.cancelled = false;
    m_tasks.emplace(id, std::move(row));
    if (!parent.empty()) {
        m_tasks[parent].children.push_back(id);
    }
    trace.Append(kAgentRunEvAddTask);
    err.clear();
    return true;
}

bool SwarmAgentRunTasks::Cancel(const std::string& id, SwarmAgentRunTrace& trace, std::string& err)
{
    const auto it = m_tasks.find(id);
    if (it == m_tasks.end()) {
        err = kAgentRunTask;
        return false;
    }
    if (it->second.cancelled) {
        err = kAgentRunReplay;
        return false;
    }
    it->second.cancelled = true;
    trace.Append(kAgentRunEvCancel);
    err.clear();
    return true;
}

bool SwarmAgentRunTasks::contains(const std::string& id) const
{
    return m_tasks.find(id) != m_tasks.end();
}

std::size_t SwarmAgentRunTasks::count() const
{
    return m_tasks.size();
}

std::string SwarmAgentRunTasks::parent_of(const std::string& id) const
{
    const auto it = m_tasks.find(id);
    if (it == m_tasks.end()) {
        return {};
    }
    return it->second.parent;
}

std::string SwarmAgentRunTasks::capability_of(const std::string& id) const
{
    const auto it = m_tasks.find(id);
    if (it == m_tasks.end()) {
        return {};
    }
    return it->second.capability;
}

std::vector<std::string> SwarmAgentRunTasks::children_of(const std::string& id) const
{
    const auto it = m_tasks.find(id);
    if (it == m_tasks.end()) {
        return {};
    }
    return it->second.children;
}

bool SwarmAgentRunTasks::cancelled(const std::string& id) const
{
    const auto it = m_tasks.find(id);
    if (it == m_tasks.end()) {
        return false;
    }
    return it->second.cancelled;
}

} // namespace modelnet
