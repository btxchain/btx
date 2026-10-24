// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_forward/policy.h>

#include <modelnet/swarm_paymesh.h>

namespace modelnet {

bool SwarmForwardPolicy::qualified() const
{
    // A presented hashlock is still not a qualified route.
    return m_route.qualified(/*hashlock_present=*/true);
}

bool SwarmForwardPolicy::broadcast() const
{
    return m_route.broadcast();
}

int64_t SwarmForwardPolicy::bytes_moved() const
{
    return 0;
}

std::string SwarmForwardPolicy::automatic_spend() const
{
    return std::string(SWARM_AUTOMATIC_SPEND_ATOMS);
}

} // namespace modelnet
