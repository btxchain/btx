// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_forward/route.h>

namespace modelnet {

bool SwarmForwardRoute::qualified(bool /*hashlock_present*/) const
{
    return false;
}

bool SwarmForwardRoute::broadcast() const
{
    return false;
}

} // namespace modelnet
