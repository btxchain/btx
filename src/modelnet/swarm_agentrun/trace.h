// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTRUN_TRACE_H
#define BITCOIN_MODELNET_SWARM_AGENTRUN_TRACE_H

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Ordered names of successful stores and of Run refusals.
 * A call that stores nothing is not appended. Run is the exception:
 * each refusal appends SANDBOX_ABSENT.
 */
class SwarmAgentRunTrace {
public:
    void Append(const std::string& event);
    std::vector<std::string> events() const;
    std::size_t size() const;

private:
    std::vector<std::string> m_events;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTRUN_TRACE_H
