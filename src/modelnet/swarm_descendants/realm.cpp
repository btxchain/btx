// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_descendants/realm.h>

#include <modelnet/swarm_descendants/limits.h>

namespace modelnet {

uint64_t SwarmDescendantRealm::bytes_moved() const
{
    return kDescendantBytesMoved;
}

bool SwarmDescendantRealm::gpu() const
{
    return false;
}

bool SwarmDescendantRealm::graduated() const
{
    return false;
}

bool SwarmDescendantRealm::promotes_realm() const
{
    return false;
}

bool SwarmDescendantRealm::mines() const
{
    return false;
}

} // namespace modelnet
