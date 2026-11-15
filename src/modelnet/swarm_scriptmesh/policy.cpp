// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_scriptmesh/policy.h>

namespace modelnet {

bool SwarmScriptMeshPolicy::qualified() const
{
    return false;
}

bool SwarmScriptMeshPolicy::secp_penalty() const
{
    return false;
}

int64_t SwarmScriptMeshPolicy::bytes_moved() const
{
    return 0;
}

bool SwarmScriptMeshPolicy::broadcast() const
{
    return false;
}

} // namespace modelnet
