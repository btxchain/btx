// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_AGENTS_BUILTIN_H
#define BTX_MODELNET_SWARM_AGENTS_BUILTIN_H

#include <modelnet/swarm_agents/types.h>

#include <string>

namespace modelnet {

/**
 * In-caller builtins. Each one leaves launched false.
 * A false return leaves out with has_result false so the caller stores nothing.
 */
bool SwarmAgentRunHold(SwarmAgentBuiltinResult& out, std::string& err);
bool SwarmAgentRunIntegerStep(SwarmAgentBuiltinResult& out, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_AGENTS_BUILTIN_H
