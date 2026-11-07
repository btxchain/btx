// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agents/trace.h>

#include <modelnet/swarm_agents/codes.h>

#include <string>
#include <vector>

namespace modelnet {

bool SwarmAgentTraceLog::Append(const std::string& task, const std::string& event, std::string& err)
{
    if (event.empty()) {
        err = kAgentTrace;
        return false;
    }
    if (task.empty()) {
        err = kAgentTask;
        return false;
    }
    SwarmAgentTraceRow row;
    row.task = task;
    row.event = event;
    m_rows.push_back(row);
    err.clear();
    return true;
}

const std::vector<SwarmAgentTraceRow>& SwarmAgentTraceLog::Rows() const
{
    return m_rows;
}

} // namespace modelnet
