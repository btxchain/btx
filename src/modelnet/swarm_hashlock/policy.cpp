// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_hashlock/policy.h>

namespace modelnet {

bool SwarmHashlockPolicy::qualified() const
{
    return false;
}

bool SwarmHashlockPolicy::broadcast() const
{
    return false;
}

int64_t SwarmHashlockPolicy::bytes_moved() const
{
    return 0;
}

int64_t SwarmHashlockPolicy::atoms_moved() const
{
    return 0;
}

} // namespace modelnet
