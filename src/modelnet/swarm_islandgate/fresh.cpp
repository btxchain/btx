// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_islandgate/fresh.h>

namespace modelnet {

bool SwarmIslandGateEpochStale(int64_t epoch, int64_t now)
{
    return epoch < now;
}

bool SwarmIslandGateEpochFresh(int64_t epoch, int64_t now)
{
    return epoch >= now;
}

} // namespace modelnet
