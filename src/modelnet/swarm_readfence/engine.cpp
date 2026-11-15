// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_readfence/engine.h>

#include <modelnet/swarm_readfence/codes.h>
#include <modelnet/swarm_readfence/names.h>

namespace modelnet {

bool SwarmReadEngine::Install(const std::string& name)
{
    if (!SwarmReadKnownEngine(name)) return false;
    m_name = name;
    m_status = kSwarmReadInstalled;
    m_installed = true;
    return true;
}

} // namespace modelnet
