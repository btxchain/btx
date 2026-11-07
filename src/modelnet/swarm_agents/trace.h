// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_AGENTS_TRACE_H
#define BTX_MODELNET_SWARM_AGENTS_TRACE_H

#include <modelnet/swarm_agents/types.h>

#include <string>
#include <vector>

namespace modelnet {

/**
 * Append-only trace of (task, event).
 * An empty event is TRACE and is not stored. An empty task is TASK
 * and is not stored. Stored rows stay in the order they were appended.
 */
class SwarmAgentTraceLog {
public:
    bool Append(const std::string& task, const std::string& event, std::string& err);
    const std::vector<SwarmAgentTraceRow>& Rows() const;

private:
    std::vector<SwarmAgentTraceRow> m_rows;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_AGENTS_TRACE_H
