// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NODEDEFAULT_GATE_H
#define BITCOIN_MODELNET_SWARM_NODEDEFAULT_GATE_H

#include <modelnet/swarm_nodedefault/limits.h>

#include <string>

namespace modelnet {

/**
 * Model-net switch for the default node.
 * modelnet_on() is true from construction. DisableModelNet is HELD and
 * does not clear it. This does not open a socket.
 */
class SwarmNodeDefaultGate {
public:
    bool modelnet_on() const;
    bool DisableModelNet(std::string& err);

private:
    bool m_on{kSwarmNodeDefaultModelNetOn};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NODEDEFAULT_GATE_H
