// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_AGENTS_REGISTRY_H
#define BTX_MODELNET_SWARM_AGENTS_REGISTRY_H

#include <modelnet/swarm_agents/types.h>

#include <string>

namespace modelnet {

/**
 * Builtin kind dispatch.
 * "hold" and "integer-step" are the only kinds that run.
 * Any other kind, including an empty kind, is UNKNOWN and does not run.
 */
class SwarmAgentRegistry {
public:
    bool Run(const std::string& kind, SwarmAgentBuiltinResult& out, std::string& err) const;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_AGENTS_REGISTRY_H
