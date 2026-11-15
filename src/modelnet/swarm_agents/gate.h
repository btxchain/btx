// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_AGENTS_GATE_H
#define BTX_MODELNET_SWARM_AGENTS_GATE_H

#include <modelnet/swarm_agents/types.h>

#include <string>

namespace modelnet {

/**
 * Sandbox gate checked before a builtin runs.
 *
 * Order, first match wins:
 *   network true is NETWORK.
 *   host_interpreter true is HOST.
 *   requested_threads outside 0..64, or requested_mib outside 0..16384, is CAPPED.
 *   a path that contains ".." or is not prefixed by a trailing-slash root is ESCAPE.
 * A refusal stores nothing. Admit does not start a child.
 */
class SwarmAgentGate {
public:
    bool Admit(const SwarmAgentRunRequest& request, std::string& err) const;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_AGENTS_GATE_H
