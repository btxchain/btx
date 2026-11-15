// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvfabric/multiplier.h>

#include <modelnet/swarm_kvfabric/codes.h>

namespace modelnet {

SwarmKvFabricResult KvFabricMultiplier::Publish(int64_t rate)
{
    // The rate argument is dropped. Nothing is stored and nothing is published.
    (void)rate;
    SwarmKvFabricResult result = KvFabricResult(kKvFabricHeld);
    result.published = false;
    return result;
}

bool KvFabricMultiplier::published() const
{
    return false;
}

bool KvFabricMultiplier::rate_stored() const
{
    return false;
}

} // namespace modelnet
