// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nodedefault/gate.h>

#include <modelnet/swarm_nodedefault/codes.h>

namespace modelnet {

bool SwarmNodeDefaultGate::modelnet_on() const
{
    return m_on;
}

bool SwarmNodeDefaultGate::DisableModelNet(std::string& err)
{
    err = kSwarmNodeDefaultHeld;
    return false;
}

} // namespace modelnet
