// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_watchhold/secret.h>

#include <modelnet/swarm_watchhold/limits.h>

namespace modelnet {

bool SwarmWatchHoldSecret::released() const
{
    return kSwarmWatchHoldSecretReleased;
}

std::size_t SwarmWatchHoldSecret::bytes() const
{
    return kSwarmWatchHoldSecretBytes;
}

} // namespace modelnet
