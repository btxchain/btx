// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_parentage/flags.h>

#include <modelnet/swarm_parentage/limits.h>

#include <cstdint>

namespace modelnet {

bool SwarmParentageFlags::trusted() const
{
    return kSwarmParentageTrusted;
}

bool SwarmParentageFlags::realm_promoted() const
{
    return kSwarmParentageRealmPromoted;
}

bool SwarmParentageFlags::exact_replay_admitted() const
{
    return kSwarmParentageExactReplayAdmitted;
}

bool SwarmParentageFlags::launched() const
{
    return kSwarmParentageLaunched;
}

bool SwarmParentageFlags::gpu() const
{
    return kSwarmParentageGpu;
}

int64_t SwarmParentageFlags::bytes_moved() const
{
    return kSwarmParentageBytesMoved;
}

} // namespace modelnet
