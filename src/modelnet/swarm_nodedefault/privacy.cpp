// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nodedefault/privacy.h>

#include <modelnet/swarm_nodedefault/codes.h>

namespace modelnet {

bool SwarmNodeDefaultPrivacy::private_prompts() const
{
    return m_private_prompts;
}

bool SwarmNodeDefaultPrivacy::EnablePrivate(std::string& err)
{
    err = kSwarmNodeDefaultHeld;
    return false;
}

} // namespace modelnet
